import { Certificate } from '../x509/Certificate.js'
import {
    dNSName,
    directoryName,
    ediPartyName,
    GeneralName,
    iPAddress,
    otherName,
    registeredID,
    rfc822Name,
    uniformResourceIdentifier,
    x400Address,
} from '../x509/GeneralName.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { GeneralSubtree, NameConstraints } from '../x509/extensions/NameConstraints.js'

/** `emailAddress` (PKCS #9), which may appear in a subject DN. */
const EMAIL_ADDRESS_OID = '1.2.840.113549.1.9.1'
/** `commonName` */
const COMMON_NAME_OID = '2.5.4.3'

/** Why a certificate was rejected by a name constraint. */
export type NameConstraintViolation = {
    /** The offending name, e.g. `www.example.com` */
    name: string
    /** What kind of name it is, e.g. `dNSName` */
    type: string
    /** A readable explanation */
    message: string
}

type NameType =
    | 'dNSName'
    | 'rfc822Name'
    | 'uniformResourceIdentifier'
    | 'iPAddress'
    | 'directoryName'
    | 'otherName'
    | 'x400Address'
    | 'ediPartyName'
    | 'registeredID'

/** The `NameType` of a GeneralName. */
function nameTypeOf(name: GeneralName): NameType {
    if (name instanceof dNSName) return 'dNSName'
    if (name instanceof rfc822Name) return 'rfc822Name'
    if (name instanceof uniformResourceIdentifier)
        return 'uniformResourceIdentifier'
    if (name instanceof iPAddress) return 'iPAddress'
    if (name instanceof directoryName) return 'directoryName'
    if (name instanceof otherName) return 'otherName'
    if (name instanceof x400Address) return 'x400Address'
    if (name instanceof ediPartyName) return 'ediPartyName'
    if (name instanceof registeredID) return 'registeredID'
    throw new Error('Unknown GeneralName type')
}

/** Types that have matching rules in RFC 5280 4.2.1.10 and are implemented here. */
const SUPPORTED: ReadonlySet<NameType> = new Set<NameType>([
    'dNSName',
    'rfc822Name',
    'uniformResourceIdentifier',
    'iPAddress',
    'directoryName',
])

// --- matching ------------------------------------------------------------------------

/**
 * A host name in comparable form: lower case, no trailing dot, internationalised labels
 * as A-labels ("bücher.example" -> "xn--bcher-kva.example", RFC 5280 7.2), so that U-label
 * and A-label spellings of a name compare equal. Leading "." or "*." prefixes are kept.
 */
export function normalizeHost(value: string): string {
    const host = value.trim().toLowerCase().replace(/\.$/, '')
    // eslint-disable-next-line no-control-regex
    if (/^[\x00-\x7f]*$/.test(host)) return host
    const prefix = /^(\*\.|\.)/.exec(host)?.[0] ?? ''
    try {
        // the WHATWG URL parser applies UTS #46 / punycode in browsers and Node alike
        return prefix + new URL(`http://${host.slice(prefix.length)}`).hostname
    } catch {
        return host // not a valid IDN: compared as is, so it matches nothing ASCII
    }
}

const normalizeDns = normalizeHost

/**
 * Whether the DNS name is the constraint or a subdomain of it (RFC 5280: "any DNS name
 * that can be constructed by simply adding zero or more labels to the left-hand side").
 * A constraint with a leading dot (".example.com") matches subdomains only.
 */
export function dnsWithin(name: string, constraint: string): boolean {
    const n = normalizeDns(name)
    const c = normalizeDns(constraint)
    if (c === '') return true
    if (c.startsWith('.')) return n.endsWith(c)
    return n === c || n.endsWith(`.${c}`)
}

/**
 * Whether a dNSName in a certificate is inside a *permitted* constraint. A wildcard
 * ("*.example.com") is inside only if everything it can match is.
 */
function dnsPermitted(name: string, constraint: string): boolean {
    const n = normalizeDns(name)
    return dnsWithin(n.startsWith('*.') ? n.slice(2) : n, constraint)
}

/**
 * Whether a dNSName in a certificate may fall inside an *excluded* constraint. A wildcard
 * is flagged when the excluded subtree sits inside the domain it covers, since the
 * wildcard could then match excluded names.
 */
function dnsExcluded(name: string, constraint: string): boolean {
    const n = normalizeDns(name)
    if (!n.startsWith('*.')) return dnsWithin(n, constraint)
    const base = n.slice(2)
    const c = normalizeDns(constraint).replace(/^\./, '')
    return dnsWithin(base, constraint) || dnsWithin(c, base)
}

/**
 * rfc822Name constraint (RFC 5280 4.2.1.10): a full mailbox matches that mailbox only; a
 * host ("example.com") matches mailboxes on exactly that host; a leading dot
 * (".example.com") matches mailboxes on any subdomain host.
 */
export function emailWithin(mailbox: string, constraint: string): boolean {
    const at = mailbox.lastIndexOf('@')
    if (at < 0) return false
    const local = mailbox.slice(0, at)
    const host = normalizeHost(mailbox.slice(at + 1))

    const constraintAt = constraint.lastIndexOf('@')
    if (constraintAt >= 0) {
        return (
            local === constraint.slice(0, constraintAt) &&
            host === normalizeHost(constraint.slice(constraintAt + 1))
        )
    }
    const c = normalizeHost(constraint)
    return c.startsWith('.') ? host.endsWith(c) : host === c
}

/** The host of a URI with an authority, or undefined (no host, or an IP literal). */
export function uriHost(uri: string): string | undefined {
    const match = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(uri)
    if (!match) return undefined
    let authority = match[1]
    authority = authority.slice(authority.lastIndexOf('@') + 1) // drop userinfo
    if (authority.startsWith('[')) return undefined // an IPv6 literal is not a DNS name
    const host = normalizeHost(authority.replace(/:\d*$/, ''))
    if (host === '' || /^\d+(\.\d+){3}$/.test(host)) return undefined // empty or IPv4 literal
    return host
}

/**
 * URI constraint (RFC 5280 4.2.1.10): applies to the host part. "host.example.com"
 * matches that host only; ".example.com" matches hosts in any subdomain.
 */
export function uriWithin(uri: string, constraint: string): boolean {
    const host = uriHost(uri)
    if (host === undefined) return false
    const c = normalizeHost(constraint)
    return c.startsWith('.') ? host.endsWith(c) : host === c
}

/**
 * iPAddress constraint: an address followed by a mask (8 bytes for IPv4, 32 for IPv6).
 * The name matches when it is the same family and equal to the address under the mask.
 */
export function ipWithin(ip: Uint8Array, constraint: Uint8Array): boolean {
    if (constraint.length !== ip.length * 2) return false
    for (let i = 0; i < ip.length; i++) {
        const mask = constraint[ip.length + i]
        if ((ip[i] & mask) !== (constraint[i] & mask)) return false
    }
    return true
}

/** A comparable form of an RDN: its attributes as "oid=value", sorted. */
function canonicalRdn(rdn: RDNSequence[number]): string {
    return [...rdn]
        .map(
            (attribute) =>
                `${attribute.type.value}=${attribute.value
                    .toHumanString()
                    .trim()
                    .replace(/\s+/g, ' ')
                    .toLowerCase()}`,
        )
        .sort()
        .join('+')
}

/** directoryName constraint: the constraint's RDNs must be a prefix of the name's. */
export function dnWithin(name: RDNSequence, constraint: RDNSequence): boolean {
    if (constraint.length > name.length) return false
    for (let i = 0; i < constraint.length; i++) {
        if (canonicalRdn(name[i]) !== canonicalRdn(constraint[i])) return false
    }
    return true
}

// --- names of a certificate ----------------------------------------------------------

type CertificateName = { type: NameType; label: string; value: GeneralName }

/**
 * The names a certificate asserts that name constraints apply to: its subjectAltName
 * entries, a non-empty subject DN (as a directoryName), and `emailAddress` attributes of
 * the subject DN (as rfc822Names), per RFC 5280 4.2.1.10.
 */
function namesOf(certificate: Certificate): {
    names: CertificateName[]
    subject: RDNSequence
} {
    const names: CertificateName[] = []

    for (const alternativeNames of certificate.getSubjectAltNames()) {
        for (const name of alternativeNames) {
            const type = nameTypeOf(name)
            names.push({ type, label: describe(name, type), value: name })
        }
    }

    const subject = certificate.tbsCertificate.subject
    if (subject.length > 0) {
        names.push({
            type: 'directoryName',
            label: subject.toHumanString(),
            value: directoryName.fromName(subject),
        })
        for (const rdn of subject) {
            for (const attribute of rdn) {
                if (attribute.type.value === EMAIL_ADDRESS_OID) {
                    const mailbox = attribute.value.toHumanString()
                    names.push({
                        type: 'rfc822Name',
                        label: mailbox,
                        value: new rfc822Name({ value: mailbox }),
                    })
                }
            }
        }
    }
    return { names, subject }
}

function describe(name: GeneralName, type: NameType): string {
    if (name instanceof iPAddress) return [...name.bytes].join('.')
    if (name instanceof directoryName) return name.toHumanString()
    return name.toString()
}

/** Whether a string can be a DNS host name (as opposed to a person's name or an acronym). */
const looksLikeHostName = (value: string) =>
    /^[A-Za-z0-9*]([A-Za-z0-9.*-]*[A-Za-z0-9])?$/.test(value) &&
    value.includes('.')

// --- the check -----------------------------------------------------------------------

/**
 * Checks a certificate against the name constraints of a CA (RFC 5280 4.2.1.10, 6.1.3(b)
 * and (c)).
 *
 * - For each kind of name, a name is acceptable only if it is inside at least one
 *   *permitted* subtree of that kind (when the CA permits any of that kind), and inside no
 *   *excluded* subtree.
 * - Kinds the constraints say nothing about are unrestricted.
 * - Anything that cannot be evaluated fails closed: constraints on name types this
 *   checker has no matching rules for (otherName, ...) when the certificate has such a
 *   name, and subtrees that use `minimum`/`maximum` (RFC 5280 forbids them).
 * - A subject common name that looks like a host name is checked as a dNSName when the
 *   certificate has no dNSName in its subjectAltName. RFC 5280 does not do this, but TLS
 *   clients have long fallen back to the CN; it can only make the check stricter.
 *
 * @returns the first violation, or `undefined` if the certificate satisfies the constraints
 */
export function checkNameConstraints(
    certificate: Certificate,
    constraints: NameConstraints,
): NameConstraintViolation | undefined {
    const permitted = [...(constraints.permittedSubtrees ?? [])]
    const excluded = [...(constraints.excludedSubtrees ?? [])]

    for (const subtree of [...permitted, ...excluded]) {
        if (subtree.minimum !== 0 || subtree.maximum !== undefined) {
            return {
                name: String(subtree.base),
                type: nameTypeOf(subtree.base),
                message:
                    'a subtree uses minimum/maximum, which RFC 5280 forbids and this validator does not support',
            }
        }
    }

    const { names } = namesOf(certificate)

    // The legacy common-name fallback (see above)
    if (!names.some((name) => name.type === 'dNSName')) {
        for (const rdn of certificate.tbsCertificate.subject) {
            for (const attribute of rdn) {
                const value = attribute.value.toHumanString()
                if (
                    attribute.type.value === COMMON_NAME_OID &&
                    looksLikeHostName(value)
                ) {
                    names.push({
                        type: 'dNSName',
                        label: value,
                        value: new dNSName({ value }),
                    })
                }
            }
        }
    }

    const ofType = (subtrees: GeneralSubtree[], type: NameType) =>
        subtrees.filter((subtree) => nameTypeOf(subtree.base) === type)

    for (const name of names) {
        const permittedOfType = ofType(permitted, name.type)
        const excludedOfType = ofType(excluded, name.type)

        if (permittedOfType.length === 0 && excludedOfType.length === 0) {
            continue // nothing constrains this kind of name
        }
        if (!SUPPORTED.has(name.type)) {
            return {
                name: name.label,
                type: name.type,
                message: `has a ${name.type}, which this validator cannot check against name constraints`,
            }
        }

        const inside = (subtree: GeneralSubtree, excludedCheck: boolean) =>
            nameInSubtree(name, subtree.base, excludedCheck)

        if (
            permittedOfType.length > 0 &&
            !permittedOfType.some((subtree) => inside(subtree, false))
        ) {
            return {
                name: name.label,
                type: name.type,
                message: `${name.type} '${name.label}' is not within any permitted subtree`,
            }
        }
        if (excludedOfType.some((subtree) => inside(subtree, true))) {
            return {
                name: name.label,
                type: name.type,
                message: `${name.type} '${name.label}' is within an excluded subtree`,
            }
        }
    }
    return undefined
}

function nameInSubtree(
    name: CertificateName,
    base: GeneralName,
    forExclusion: boolean,
): boolean {
    const value = name.value
    if (value instanceof dNSName && base instanceof dNSName) {
        return forExclusion
            ? dnsExcluded(value.toString(), base.toString())
            : dnsPermitted(value.toString(), base.toString())
    }
    if (value instanceof rfc822Name && base instanceof rfc822Name) {
        return emailWithin(value.toString(), base.toString())
    }
    if (
        value instanceof uniformResourceIdentifier &&
        base instanceof uniformResourceIdentifier
    ) {
        return uriWithin(value.toString(), base.toString())
    }
    if (value instanceof iPAddress && base instanceof iPAddress) {
        return ipWithin(value.bytes, base.bytes)
    }
    if (value instanceof directoryName && base instanceof directoryName) {
        return dnWithin(value, base)
    }
    return false
}
