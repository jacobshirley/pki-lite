import { Certificate } from '../x509/Certificate.js'
import { Extension } from '../x509/Extension.js'
import { GeneralName } from '../x509/GeneralName.js'
import { AuthorityKeyIdentifier } from '../x509/extensions/AuthorityKeyIdentifier.js'
import { BasicConstraints } from '../x509/extensions/BasicConstraints.js'
import { ExtKeyUsage } from '../x509/extensions/ExtKeyUsage.js'
import { NameConstraints } from '../x509/extensions/NameConstraints.js'
import { SubjectAltName } from '../x509/extensions/SubjectAltName.js'
import { OIDs } from './OIDs.js'

/** A DNS name in preferred name syntax: letter-digit-hyphen labels (RFC 5280 4.2.1.6). */
const LDH_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i

function validDnsName(name: string, allowWildcard: boolean): boolean {
    if (name.length === 0 || name.length > 253) return false
    const labels = name.split('.')
    return labels.every(
        (label, i) =>
            LDH_LABEL.test(label) ||
            (allowWildcard && i === 0 && label === '*'),
    )
}

/** An email address with exactly one `@`, a local part and a valid domain. */
function validMailbox(mailbox: string): boolean {
    const parts = mailbox.split('@')
    return (
        parts.length === 2 &&
        parts[0].length > 0 &&
        validDnsName(parts[1], false)
    )
}

/** A malformed name in a subjectAltName, if any. */
function malformedName(name: GeneralName): string | undefined {
    if (name instanceof GeneralName.dNSName) {
        const value = name.toString()
        return validDnsName(value, true) ? undefined : `dNSName '${value}'`
    }
    if (name instanceof GeneralName.rfc822Name) {
        const value = name.toString()
        return validMailbox(value) ? undefined : `rfc822Name '${value}'`
    }
    if (name instanceof GeneralName.iPAddress) {
        const length = name.bytes.length
        return length === 4 || length === 16
            ? undefined
            : `iPAddress of ${length} bytes`
    }
    return undefined
}

/**
 * Where a certificate breaks the RFC 5280 certificate profile: the rules for what
 * conforming CAs issue (section 4), as opposed to the path validation algorithm
 * (section 6). Many real PKIs break some of them, so CertificateValidator checks them only
 * with `strictProfile`, as OpenSSL does only with its X509_STRICT flag.
 *
 * A trust anchor is checked as a CA, but not for the rules about how it was issued (its
 * serial number, and an authorityKeyIdentifier when it is not self-signed): RFC 5280 does
 * not validate trust anchor information, and real roots break them (fastly.com's chain
 * ends at a Starfield root with serial number 0).
 *
 * @param certificate The certificate to check
 * @param options.trustAnchor Whether it is the trust anchor of the path
 * @returns A description of each problem found (none if it conforms)
 */
export function checkCertificateProfile(
    certificate: Certificate,
    options: { trustAnchor?: boolean } = {},
): string[] {
    const problems: string[] = []
    const tbs = certificate.tbsCertificate
    const extensions = tbs.extensions ?? []
    const find = (oid: string) =>
        extensions.find((extension) => extension.extnID.value === oid)
    const parse = <T>(
        extension: Extension | undefined,
        type: { fromAsn1(asn1: never): T },
    ): T | undefined => {
        if (!extension) return undefined
        try {
            return extension.extnValue.parseAs(type as never) as T
        } catch {
            problems.push(`a malformed ${extension.extnID.value} extension`)
            return undefined
        }
    }

    // 4.2: an extension may appear only once
    const seen = new Set<string>()
    for (const extension of extensions) {
        const oid = extension.extnID.value
        if (seen.has(oid)) problems.push(`the ${oid} extension appears twice`)
        seen.add(oid)
    }

    // 4.1.2.2: the serial number is a positive integer of at most 20 octets
    const serial = tbs.serialNumber
    if (options.trustAnchor) {
        // not checked for a trust anchor (see above)
    } else if (serial.bytes.length > 20) {
        problems.push('the serial number is longer than 20 octets')
    } else if (serial.toBigInt() <= 0n) {
        problems.push('the serial number is not positive')
    }

    const basicConstraintsExtension = find(OIDs.EXTENSION.BASIC_CONSTRAINTS)
    const isCa = parse(basicConstraintsExtension, BasicConstraints)?.cA ?? false
    const selfIssued = tbs.issuer.matches(tbs.subject)

    // 4.2.1.1: authorityKeyIdentifier, non-critical, with a keyIdentifier, in every
    // certificate except a self-signed one
    const aki = find(OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER)
    if (aki?.critical) {
        problems.push('the authorityKeyIdentifier extension is critical')
    }
    if (
        !selfIssued &&
        !options.trustAnchor &&
        !parse(aki, AuthorityKeyIdentifier)?.keyIdentifier
    ) {
        problems.push('no authorityKeyIdentifier keyIdentifier')
    }

    // 4.2.1.2: subjectKeyIdentifier, non-critical, in every CA certificate
    const ski = find(OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER)
    if (ski?.critical) {
        problems.push('the subjectKeyIdentifier extension is critical')
    }
    if (isCa && !ski)
        problems.push('a CA certificate without subjectKeyIdentifier')

    // 4.2.1.9: basicConstraints is critical in a CA certificate
    if (isCa && !basicConstraintsExtension?.critical) {
        problems.push('the basicConstraints extension of a CA is not critical')
    }

    // 4.2.1.3: keyCertSign only with cA
    const keyUsage = find(OIDs.EXTENSION.KEY_USAGE)
    if (keyUsage && !isCa && certificate.allowsKeyUsage('keyCertSign')) {
        problems.push('keyCertSign in a certificate that is not a CA')
    }

    // 4.1.2.6: a CA has a non-empty subject
    if (isCa && tbs.subject.length === 0) {
        problems.push('a CA certificate with an empty subject')
    }

    // 4.2.1.6: subjectAltName, critical if the subject is empty, with well-formed names
    const sanExtension = find(OIDs.EXTENSION.SUBJECT_ALT_NAME)
    if (tbs.subject.length === 0 && !sanExtension?.critical) {
        problems.push(
            'an empty subject without a critical subjectAltName extension',
        )
    }
    for (const name of parse(sanExtension, SubjectAltName) ?? []) {
        const malformed = malformedName(name)
        if (malformed) problems.push(`a malformed subjectAltName ${malformed}`)
    }

    // 4.2.1.10: nameConstraints only in a CA, critical, with non-empty subtrees and
    // well-formed DNS name bases
    const nameConstraintsExtension = find(OIDs.EXTENSION.NAME_CONSTRAINTS)
    if (nameConstraintsExtension) {
        if (!isCa)
            problems.push('nameConstraints in a certificate that is not a CA')
        if (!nameConstraintsExtension.critical) {
            problems.push('the nameConstraints extension is not critical')
        }
        const constraints = parse(nameConstraintsExtension, NameConstraints)
        for (const [kind, subtrees] of [
            ['permitted', constraints?.permittedSubtrees],
            ['excluded', constraints?.excludedSubtrees],
        ] as const) {
            if (subtrees && subtrees.length === 0) {
                problems.push(`empty ${kind}Subtrees in nameConstraints`)
            }
            for (const subtree of subtrees ?? []) {
                const base = subtree.base
                if (
                    base instanceof GeneralName.dNSName &&
                    base.toString() !== '' &&
                    !validDnsName(base.toString(), false)
                ) {
                    problems.push(
                        `a malformed dNSName constraint '${base.toString()}'`,
                    )
                }
            }
        }
    }

    // 4.2.1.11: policyConstraints is critical
    const policyConstraints = find(OIDs.EXTENSION.POLICY_CONSTRAINTS)
    if (policyConstraints && !policyConstraints.critical) {
        problems.push('the policyConstraints extension is not critical')
    }

    // 4.2.1.12: extKeyUsage lists at least one purpose
    const eku = parse(find(OIDs.EXTENSION.EXTENDED_KEY_USAGE), ExtKeyUsage)
    if (eku && eku.length === 0) problems.push('an empty extendedKeyUsage')

    // 4.2.2.1: authorityInfoAccess is non-critical
    if (find(OIDs.EXTENSION.AUTHORITY_INFO_ACCESS)?.critical) {
        problems.push('the authorityInfoAccess extension is critical')
    }

    return problems
}
