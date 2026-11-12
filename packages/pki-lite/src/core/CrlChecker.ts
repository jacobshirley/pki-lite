import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { RevokedCertificate } from '../x509/RevokedCertificate.js'
import { Extension } from '../x509/Extension.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import {
    directoryName,
    GeneralName,
    GeneralNames,
} from '../x509/GeneralName.js'
import { BasicConstraints } from '../x509/extensions/BasicConstraints.js'
import { KeyUsage } from '../x509/extensions/KeyUsage.js'
import {
    CRLDistributionPoints,
    DistributionPoint,
} from '../x509/extensions/CRLDistributionPoints.js'
import { IssuingDistributionPoint } from '../x509/extensions/IssuingDistributionPoint.js'
import { ReasonFlags } from '../x509/ReasonFlags.js'
import { CRLReason } from '../x509/CRLReason.js'
import { Integer } from '../asn1/Integer.js'
import { SignatureAlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from './OIDs.js'
import { derToAsn1 } from './PkiBase.js'
import { namesMatch } from './NameMatching.js'
import { signedBytes } from './OriginalEncoding.js'

/** The revocation reasons a set of CRLs has to cover between them (RFC 5280 6.3.3). */
const ALL_REASONS = [
    'keyCompromise',
    'cACompromise',
    'affiliationChanged',
    'superseded',
    'cessationOfOperation',
    'certificateHold',
    'privilegeWithdrawn',
    'aACompromise',
] as const
type Reason = (typeof ALL_REASONS)[number]

/** CRL extensions this checker understands (a critical one it does not makes the CRL unusable). */
const KNOWN_CRL_EXTENSIONS = new Set<string>([
    OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER,
    OIDs.EXTENSION.CRL_NUMBER,
    OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
    OIDs.EXTENSION.DELTA_CRL_INDICATOR,
    OIDs.EXTENSION.FRESHEST_CRL,
    OIDs.EXTENSION.AUTHORITY_INFO_ACCESS,
    OIDs.EXTENSION.ISSUER_ALT_NAME,
])

/** CRL entry extensions this checker understands. */
const KNOWN_ENTRY_EXTENSIONS = new Set<string>([
    OIDs.EXTENSION.CRL_REASON_CODE,
    OIDs.EXTENSION.CERTIFICATE_ISSUER,
    OIDs.EXTENSION.INVALIDITY_DATE,
    OIDs.EXTENSION.HOLD_INSTRUCTION_CODE,
])

/** CRLReason removeFromCRL: a delta CRL lifting a hold listed on the base CRL */
const REMOVE_FROM_CRL = 8

export type CrlStatus = {
    /** good: not revoked by CRLs covering every reason; undetermined: no such CRLs */
    status: 'good' | 'revoked' | 'undetermined'
    reason?: number
    revocationTime?: Date
    details: string
}

export type CrlCheckerOptions = {
    /** The CRLs available */
    crls: CertificateList[]
    /** Every certificate available to find CRL signers among (path, extras, anchors) */
    certificates: Certificate[]
    /** Trust anchor certificates: trusted as CRL signers without a path */
    trustAnchors: Certificate[]
    /** The time to check at */
    time: Date
    /**
     * Validates the certification path of a CRL signer that is not a trust anchor,
     * including its own revocation status (RFC 5280 6.3.3 (f)).
     */
    validateSigner: (signer: Certificate) => Promise<boolean>
}

const extensionOf = (extensions: Extension[] | undefined, oid: string) =>
    extensions?.find((extension) => extension.extnID.value === oid)

const parseExtension = <T>(
    extension: Extension | undefined,
    type: { fromAsn1(asn1: ReturnType<typeof derToAsn1>): T },
): T | undefined =>
    extension ? type.fromAsn1(derToAsn1(extension.extnValue.bytes)) : undefined

const reasonsOf = (flags: ReasonFlags | undefined): Set<Reason> =>
    new Set(flags ? ALL_REASONS.filter((reason) => flags[reason]) : ALL_REASONS)

const crlNumberOf = (crl: CertificateList, oid: string): bigint | undefined => {
    const extension = extensionOf(crl.tbsCertList.extensions, oid)
    return extension
        ? Integer.fromAsn1(derToAsn1(extension.extnValue.bytes)).toBigInt()
        : undefined
}

const isCa = (certificate: Certificate) => {
    const extension = certificate.getExtensionByOid(
        OIDs.EXTENSION.BASIC_CONSTRAINTS,
    )
    return extension ? extension.extnValue.parseAs(BasicConstraints).cA : false
}

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
    a.length === b.length && a.every((byte, i) => byte === b[i])

/** Whether two GeneralNames are the same name (directory names per RFC 5280 7.1). */
function generalNamesEqual(a: GeneralName, b: GeneralName): boolean {
    if (a instanceof directoryName && b instanceof directoryName) {
        return namesMatch(a, b)
    }
    return a.constructor === b.constructor && sameBytes(a.toDer(), b.toDer())
}

/** The full names a distribution point name stands for (RFC 5280 4.2.1.13). */
function fullNames(
    name: GeneralNames | RelativeDistinguishedName | undefined,
    crlIssuer: RDNSequence,
): GeneralName[] {
    if (!name) return []
    if (name instanceof RelativeDistinguishedName) {
        // nameRelativeToCRLIssuer: the CRL issuer's name with this RDN appended
        const full = new RDNSequence(...crlIssuer, name)
        return [directoryName.fromName(full)]
    }
    return [...name]
}

/**
 * Determines a certificate's revocation status from CRLs as RFC 5280 6.3 describes:
 * complete CRLs (and delta CRLs on top of them) are used only if they are issued for the
 * certificate (directly or, for an indirect CRL, by a cRLIssuer the certificate names),
 * apply to it (issuingDistributionPoint scope), are current, have no critical extension
 * this checker cannot process, and are signed by a key whose certificate allows CRL
 * signing and validates. A certificate is "good" only if such CRLs cover every
 * revocation reason; otherwise its status is undetermined.
 */
export class CrlChecker {
    private readonly options: CrlCheckerOptions

    constructor(options: CrlCheckerOptions) {
        this.options = options
    }

    async check(certificate: Certificate): Promise<CrlStatus> {
        const extension = certificate.getExtensionByOid(
            OIDs.EXTENSION.CRL_DISTRIBUTION_POINTS,
        )
        const points = extension
            ? [...extension.extnValue.parseAs(CRLDistributionPoints)]
            : []
        // a certificate without distribution points is covered by its issuer's CRLs
        if (points.length === 0) points.push(new DistributionPoint())

        const covered = new Set<Reason>()
        const problems: string[] = []

        for (const point of points) {
            for (const crl of this.completeCrls()) {
                const interim = await this.usableFor(
                    certificate,
                    point,
                    crl,
                    problems,
                )
                if (!interim) continue

                const deltas = await this.deltasFor(crl, problems)
                const entry = this.findEntry(certificate, crl, deltas)
                if (entry && entry.reason !== REMOVE_FROM_CRL) {
                    return {
                        status: 'revoked',
                        reason: entry.reason,
                        revocationTime: entry.entry.revocationDate,
                        details: `Certificate found in the CRL of '${crl.tbsCertList.issuer.toHumanString()}'`,
                    }
                }
                for (const reason of interim) covered.add(reason)
            }
        }

        // every usable CRL is consulted (a revocation on any of them counts) rather than
        // stopping once the reasons are covered as 6.3.3 does: it assumes a cache holding
        // only the latest CRLs, while the CRLs given here can include older or duplicate
        // ones
        if (covered.size === ALL_REASONS.length) {
            return { status: 'good', details: 'Not revoked (CRL)' }
        }
        return {
            status: 'undetermined',
            details:
                problems.length > 0
                    ? `No usable CRL covers this certificate: ${[...new Set(problems)].join('; ')}`
                    : 'No CRL covers this certificate',
        }
    }

    private completeCrls(): CertificateList[] {
        return this.options.crls.filter(
            (crl) =>
                !extensionOf(
                    crl.tbsCertList.extensions,
                    OIDs.EXTENSION.DELTA_CRL_INDICATOR,
                ),
        )
    }

    /**
     * RFC 5280 6.3.3 (a) to (i) for one complete CRL: the reasons it covers for
     * this certificate and distribution point, or undefined if it cannot be used.
     */
    private async usableFor(
        certificate: Certificate,
        point: DistributionPoint,
        crl: CertificateList,
        problems: string[],
    ): Promise<Set<Reason> | undefined> {
        const tbs = crl.tbsCertList
        const issuer = tbs.issuer
        const idp = parseExtension(
            extensionOf(
                tbs.extensions,
                OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
            ),
            IssuingDistributionPoint,
        )

        // (b)(1) issued for this certificate: by its issuer, or, for an indirect CRL, by
        // one of the cRLIssuer names of the distribution point
        if (point.cRLIssuer) {
            const named = [...point.cRLIssuer].some(
                (name) =>
                    name instanceof directoryName && namesMatch(name, issuer),
            )
            if (!named || !idp?.indirectCRL) return undefined
        } else if (!namesMatch(issuer, certificate.tbsCertificate.issuer)) {
            return undefined
        }

        // (b)(2) scope
        if (idp) {
            const idpNames = fullNames(idp.distributionPoint, issuer)
            if (idpNames.length > 0) {
                const pointNames = point.distributionPoint
                    ? fullNames(point.distributionPoint, issuer)
                    : [...(point.cRLIssuer ?? [])]
                const shared = idpNames.some((a) =>
                    pointNames.some((b) => generalNamesEqual(a, b)),
                )
                if (!shared) {
                    problems.push('a CRL is for another distribution point')
                    return undefined
                }
            }
            if (idp.onlyContainsUserCerts && isCa(certificate)) {
                problems.push('a CRL only covers end-entity certificates')
                return undefined
            }
            if (idp.onlyContainsCACerts && !isCa(certificate)) {
                problems.push('a CRL only covers CA certificates')
                return undefined
            }
            if (idp.onlyContainsAttributeCerts) {
                problems.push('a CRL only covers attribute certificates')
                return undefined
            }
        }

        // (d)/(e) the reasons this CRL covers for this distribution point, if any
        const interim = reasonsOf(idp?.onlySomeReasons)
        const pointReasons = reasonsOf(point.reasons)
        for (const reason of [...interim]) {
            if (!pointReasons.has(reason)) interim.delete(reason)
        }
        if (interim.size === 0) return undefined

        // (a) current
        const problem = this.crlProblem(crl)
        if (problem) {
            problems.push(problem)
            return undefined
        }

        // (f)/(g) signed by a key allowed to sign CRLs, whose path validates
        if (!(await this.verifySignature(crl))) {
            problems.push(
                `the CRL of '${issuer.toHumanString()}' has no valid signature from a CRL signer that validates`,
            )
            return undefined
        }
        return interim
    }

    /** Why a CRL cannot be used regardless of the certificate, if it cannot. */
    private crlProblem(crl: CertificateList): string | undefined {
        const tbs = crl.tbsCertList
        const name = `the CRL of '${tbs.issuer.toHumanString()}'`
        const time = this.options.time
        if (tbs.thisUpdate > time) return `${name} is not yet valid`
        // RFC 5280 5.1.2.5: conforming CRLs include nextUpdate; without it, freshness
        // cannot be established
        if (!tbs.nextUpdate) return `${name} has no nextUpdate`
        if (tbs.nextUpdate < time)
            return `${name} is out of date (nextUpdate ${tbs.nextUpdate.toISOString()})`
        for (const extension of tbs.extensions ?? []) {
            if (
                extension.critical &&
                !KNOWN_CRL_EXTENSIONS.has(extension.extnID.value)
            ) {
                return `${name} has an unsupported critical extension ${extension.extnID.value}`
            }
        }
        for (const entry of tbs.revokedCertificates ?? []) {
            for (const extension of entry.crlEntryExtensions ?? []) {
                if (
                    extension.critical &&
                    !KNOWN_ENTRY_EXTENSIONS.has(extension.extnID.value)
                ) {
                    return `${name} has an entry with an unsupported critical extension ${extension.extnID.value}`
                }
            }
        }
        return undefined
    }

    /** Whether a CRL is signed by a certificate with its issuer's name that may sign CRLs. */
    private async verifySignature(crl: CertificateList): Promise<boolean> {
        const issuer = crl.tbsCertList.issuer
        const algorithm = new SignatureAlgorithmIdentifier(
            crl.signatureAlgorithm,
        )
        const bytes = signedBytes(crl.tbsCertList)
        for (const signer of this.options.certificates) {
            if (!namesMatch(signer.tbsCertificate.subject, issuer)) continue
            const keyUsage = signer.getExtensionByOid(OIDs.EXTENSION.KEY_USAGE)
            if (keyUsage && !keyUsage.extnValue.parseAs(KeyUsage).cRLSign)
                continue
            let valid = false
            try {
                valid = await algorithm.verify(
                    bytes,
                    crl.signatureValue.bytes,
                    signer.getSubjectPublicKeyInfo(),
                )
            } catch {
                valid = false
            }
            if (!valid) continue
            const anchor = this.options.trustAnchors.some((trusted) =>
                trusted.equals(signer),
            )
            if (anchor || (await this.options.validateSigner(signer)))
                return true
        }
        return false
    }

    /** Delta CRLs usable on top of a complete CRL (RFC 5280 5.2.4, 6.3.3 (c)). */
    private async deltasFor(
        base: CertificateList,
        problems: string[],
    ): Promise<CertificateList[]> {
        const baseNumber = crlNumberOf(base, OIDs.EXTENSION.CRL_NUMBER)
        const usable: CertificateList[] = []
        for (const delta of this.options.crls) {
            const baseOfDelta = crlNumberOf(
                delta,
                OIDs.EXTENSION.DELTA_CRL_INDICATOR,
            )
            if (baseOfDelta === undefined || baseNumber === undefined) continue
            if (!namesMatch(delta.tbsCertList.issuer, base.tbsCertList.issuer))
                continue
            // the delta must build on this complete CRL or an earlier one
            if (baseOfDelta > baseNumber) continue
            const sameScope = sameBytes(
                extensionOf(
                    delta.tbsCertList.extensions,
                    OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
                )?.extnValue.bytes ?? new Uint8Array(),
                extensionOf(
                    base.tbsCertList.extensions,
                    OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
                )?.extnValue.bytes ?? new Uint8Array(),
            )
            if (!sameScope) continue
            const problem = this.crlProblem(delta)
            if (problem) {
                problems.push(problem.replace('the CRL', 'the delta CRL'))
                continue
            }
            if (!(await this.verifySignature(delta))) {
                problems.push('a delta CRL has no valid signature')
                continue
            }
            usable.push(delta)
        }
        return usable
    }

    /**
     * The entry for a certificate on a complete CRL and its deltas: the latest one, since
     * a delta can add a revocation or (with removeFromCRL) lift a hold.
     */
    private findEntry(
        certificate: Certificate,
        base: CertificateList,
        deltas: CertificateList[],
    ): { entry: RevokedCertificate; reason?: number } | undefined {
        let found: { entry: RevokedCertificate; reason?: number } | undefined
        for (const crl of [base, ...deltas]) {
            const entry = this.entryOn(certificate, crl)
            if (entry) found = entry
        }
        return found
    }

    private entryOn(
        certificate: Certificate,
        crl: CertificateList,
    ): { entry: RevokedCertificate; reason?: number } | undefined {
        const serial = certificate.tbsCertificate.serialNumber.toBigInt()
        const idp = parseExtension(
            extensionOf(
                crl.tbsCertList.extensions,
                OIDs.EXTENSION.ISSUING_DISTRIBUTION_POINT,
            ),
            IssuingDistributionPoint,
        )
        // on an indirect CRL, entries name their certificate issuer (RFC 5280 5.3.3): it
        // applies to that entry and the ones after it, starting from the CRL issuer
        let entryIssuer: GeneralName[] = [
            directoryName.fromName(crl.tbsCertList.issuer),
        ]
        for (const entry of crl.tbsCertList.revokedCertificates ?? []) {
            const issuerExtension = extensionOf(
                entry.crlEntryExtensions,
                OIDs.EXTENSION.CERTIFICATE_ISSUER,
            )
            if (issuerExtension && idp?.indirectCRL) {
                entryIssuer = [
                    ...GeneralNames.fromAsn1(
                        derToAsn1(issuerExtension.extnValue.bytes),
                    ),
                ]
            }
            if (entry.serialAsBigInt() !== serial) continue
            const issuedBy = entryIssuer.some(
                (name) =>
                    name instanceof directoryName &&
                    namesMatch(name, certificate.tbsCertificate.issuer),
            )
            if (!issuedBy) continue
            const reasonExtension = extensionOf(
                entry.crlEntryExtensions,
                OIDs.EXTENSION.CRL_REASON_CODE,
            )
            return {
                entry,
                reason: reasonExtension?.extnValue.parseAs(CRLReason).value,
            }
        }
        return undefined
    }
}
