import { asn1js } from './PkiBase.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'

/** The ASN.1 string types a DirectoryString (or an emailAddress, ...) can use. */
const STRING_TYPES = [
    asn1js.Utf8String,
    asn1js.PrintableString,
    asn1js.TeletexString,
    asn1js.BmpString,
    asn1js.UniversalString,
    asn1js.IA5String,
    asn1js.VisibleString,
]

const hex = (bytes: Uint8Array) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

/**
 * An attribute value in comparable form (RFC 5280 7.1, which applies RFC 4518 string
 * preparation): a character string, whatever its ASN.1 string type, is Unicode-normalised
 * (NFKC), case-folded, and has leading, trailing and repeated whitespace removed, so that
 * PrintableString "Test  CA" and UTF8String "test ca" compare equal. Any other value is
 * compared by its DER encoding.
 */
export function canonicalAttributeValue(
    attribute: AttributeTypeAndValue,
): string {
    const asn1 = attribute.value.toAsn1()
    if (STRING_TYPES.some((type) => asn1 instanceof type)) {
        const text = attribute.value.toHumanString()
        return `s:${text.normalize('NFKC').toLowerCase().trim().replace(/\s+/g, ' ')}`
    }
    return `d:${hex(attribute.value.toDer())}`
}

/** An RDN in comparable form: its attributes, each `type=value`, in a fixed order. */
export function canonicalRdn(rdn: RDNSequence[number]): string {
    return [...rdn]
        .map(
            (attribute) =>
                `${attribute.type.value}=${canonicalAttributeValue(attribute)}`,
        )
        .sort()
        .join('+')
}

/**
 * Whether two distinguished names match (RFC 5280 7.1): the same number of RDNs, and each
 * RDN with the same set of attribute types and matching values.
 */
export function namesMatch(a: RDNSequence, b: RDNSequence): boolean {
    return a.length === b.length && nameWithin(a, b)
}

/** Whether `constraint`'s RDNs are a prefix of `name`'s (a directoryName subtree). */
export function nameWithin(
    name: RDNSequence,
    constraint: RDNSequence,
): boolean {
    if (constraint.length > name.length) return false
    for (let i = 0; i < constraint.length; i++) {
        if (canonicalRdn(name[i]) !== canonicalRdn(constraint[i])) return false
    }
    return true
}
