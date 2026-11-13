import { Certificate } from '../x509/Certificate.js'
import { CertificateList } from '../x509/CertificateList.js'
import { RevokedCertificate } from '../x509/RevokedCertificate.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import {
    directoryName,
    GeneralName,
    GeneralNames,
} from '../x509/GeneralName.js'
import { DistributionPoint } from '../x509/extensions/CRLDistributionPoints.js'
import { ReasonFlags } from '../x509/ReasonFlags.js'
import { OIDs } from './OIDs.js'

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

const reasonsOf = (flags: ReasonFlags | undefined): Set<Reason> =>
    new Set(flags ? ALL_REASONS.filter((reason) => flags[reason]) : ALL_REASONS)

/** Whether two GeneralNames are the same name (directory names per RFC 5280 7.1). */
const sameName = (a: GeneralName, b: GeneralName): boolean =>
    a instanceof directoryName && b instanceof directoryName
        ? a.matches(b)
        : String(a.toDer()) === String(b.toDer())

/** The full names a distribution point name stands for (RFC 5280 4.2.1.13). */
function fullNames(
    name: GeneralNames | RelativeDistinguishedName | undefined,
    crlIssuer: RDNSequence,
): GeneralName[] {
    if (!name) return []
    if (name instanceof RelativeDistinguishedName) {
        // nameRelativeToCRLIssuer: the CRL issuer's name with this RDN appended
        return [directoryName.fromName(new RDNSequence(...crlIssuer, name))]
    }
    return [...name]
}

/** Whether two CRLs have the same scope (the same issuingDistributionPoint, or none). */
function sameScope(a: CertificateList, b: CertificateList): boolean {
    const scopeA = a.getExtensionByName('ISSUING_DISTRIBUTION_POINT')?.extnValue
    const scopeB = b.getExtensionByName('ISSUING_DISTRIBUTION_POINT')?.extnValue
    return scopeA && scopeB ? scopeA.equals(scopeB) : scopeA === scopeB
}

/**
 * Determines a certificate's revocation status from CRLs as RFC 5280 6.3 describes:
 * complete CRLs (and delta CRLs on top of them) are used only if they are issued for the
 * certificate (directly or, for an indirect CRL, by a cRLIssuer the certificate names),
 * apply to it (issuingDistributionPoint scope), are current, have no critical extension
 * this checker cannot process, and are signed by a key whose certificate allows CRL
 * signing and validates. A certificate is "good" only if such CRLs cover every
 * revocation reason; otherwise its status is undetermined.
 *
 * For a single CRL, `crl.verify(issuer)`, `crl.isCurrent()` and `crl.isRevoked(cert)` do
 * the individual checks; CertificateValidator uses this class with `checkCRL`.
 */
export class CrlChecker {
    private readonly options: CrlCheckerOptions

    constructor(options: CrlCheckerOptions) {
        this.options = options
    }

    async check(certificate: Certificate): Promise<CrlStatus> {
        const points = certificate.getCrlDistributionPoints()
        // a certificate without distribution points is covered by its issuer's CRLs
        if (points.length === 0) points.push(new DistributionPoint())

        const covered = new Set<Reason>()
        const problems: string[] = []

        for (const point of points) {
            for (const crl of this.options.crls.filter((c) => !c.isDelta)) {
                const reasons = await this.usableFor(
                    certificate,
                    point,
                    crl,
                    problems,
                )
                if (!reasons) continue

                const deltas = await this.deltasFor(crl, problems)
                const entry = this.findEntry(certificate, crl, deltas)
                if (entry && entry.reason !== REMOVE_FROM_CRL) {
                    return {
                        status: 'revoked',
                        reason: entry.reason,
                        revocationTime: entry.revocationDate,
                        details: `Certificate found in the CRL of '${crl.tbsCertList.issuer.toHumanString()}'`,
                    }
                }
                for (const reason of reasons) covered.add(reason)
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

    /**
     * RFC 5280 6.3.3 (a) to (i) for one complete CRL: the reasons it covers for this
     * certificate and distribution point, or undefined if it cannot be used.
     */
    private async usableFor(
        certificate: Certificate,
        point: DistributionPoint,
        crl: CertificateList,
        problems: string[],
    ): Promise<Set<Reason> | undefined> {
        const issuer = crl.tbsCertList.issuer
        const idp = crl.issuingDistributionPoint

        // (b)(1) issued for this certificate: by its issuer, or, for an indirect CRL, by
        // one of the cRLIssuer names of the distribution point
        if (point.cRLIssuer) {
            const named = [...point.cRLIssuer].some(
                (name) => name instanceof directoryName && name.matches(issuer),
            )
            if (!named || !idp?.indirectCRL) return undefined
        } else if (!issuer.matches(certificate.tbsCertificate.issuer)) {
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
                    pointNames.some((b) => sameName(a, b)),
                )
                if (!shared) {
                    problems.push('a CRL is for another distribution point')
                    return undefined
                }
            }
            if (idp.onlyContainsUserCerts && certificate.isCA()) {
                problems.push('a CRL only covers end-entity certificates')
                return undefined
            }
            if (idp.onlyContainsCACerts && !certificate.isCA()) {
                problems.push('a CRL only covers CA certificates')
                return undefined
            }
            if (idp.onlyContainsAttributeCerts) {
                problems.push('a CRL only covers attribute certificates')
                return undefined
            }
        }

        // (d)/(e) the reasons this CRL covers for this distribution point, if any
        const reasons = reasonsOf(idp?.onlySomeReasons)
        const pointReasons = reasonsOf(point.reasons)
        for (const reason of [...reasons]) {
            if (!pointReasons.has(reason)) reasons.delete(reason)
        }
        if (reasons.size === 0) return undefined

        // (a) current
        const problem = this.crlProblem(crl)
        if (problem) {
            problems.push(problem)
            return undefined
        }

        // (f)/(g) signed by a key allowed to sign CRLs, whose path validates
        if (!(await this.signedByValidSigner(crl))) {
            problems.push(
                `the CRL of '${issuer.toHumanString()}' has no valid signature from a CRL signer that validates`,
            )
            return undefined
        }
        return reasons
    }

    /** Why a CRL cannot be used regardless of the certificate, if it cannot. */
    private crlProblem(crl: CertificateList): string | undefined {
        const { thisUpdate, nextUpdate, extensions, revokedCertificates } =
            crl.tbsCertList
        const name = `the CRL of '${crl.tbsCertList.issuer.toHumanString()}'`
        if (!crl.isCurrent(this.options.time)) {
            if (thisUpdate > this.options.time)
                return `${name} is not yet valid`
            // RFC 5280 5.1.2.5: conforming CRLs include nextUpdate; without it,
            // freshness cannot be established
            if (!nextUpdate) return `${name} has no nextUpdate`
            return `${name} is out of date (nextUpdate ${nextUpdate.toISOString()})`
        }
        for (const extension of extensions ?? []) {
            if (
                extension.critical &&
                !KNOWN_CRL_EXTENSIONS.has(extension.extnID.value)
            ) {
                return `${name} has an unsupported critical extension ${extension.extnID.value}`
            }
        }
        for (const entry of revokedCertificates ?? []) {
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

    /** Whether a CRL verifies with an available signer that is trusted or validates. */
    private async signedByValidSigner(crl: CertificateList): Promise<boolean> {
        for (const signer of this.options.certificates) {
            let signed = false
            try {
                signed = await crl.verify(signer)
            } catch {
                // an unsupported algorithm or malformed key: not a usable signature
            }
            if (!signed) continue
            const anchor = this.options.trustAnchors.some((trusted) =>
                trusted.equals(signer),
            )
            if (anchor || (await this.options.validateSigner(signer))) {
                return true
            }
        }
        return false
    }

    /** Delta CRLs usable on top of a complete CRL (RFC 5280 5.2.4, 6.3.3 (c)). */
    private async deltasFor(
        base: CertificateList,
        problems: string[],
    ): Promise<CertificateList[]> {
        const baseNumber = base.crlNumber
        if (baseNumber === undefined) return []
        const usable: CertificateList[] = []
        for (const delta of this.options.crls) {
            const deltaBase = delta.baseCrlNumber
            if (deltaBase === undefined) continue
            if (!delta.tbsCertList.issuer.matches(base.tbsCertList.issuer)) {
                continue
            }
            // the delta must build on this complete CRL or an earlier one, with its scope
            if (deltaBase > baseNumber || !sameScope(delta, base)) continue
            const problem = this.crlProblem(delta)
            if (problem) {
                problems.push(problem.replace('the CRL', 'the delta CRL'))
                continue
            }
            if (!(await this.signedByValidSigner(delta))) {
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
    ): RevokedCertificate | undefined {
        let found: RevokedCertificate | undefined
        for (const crl of [base, ...deltas]) {
            found = crl.getRevokedEntry(certificate) ?? found
        }
        return found
    }
}
