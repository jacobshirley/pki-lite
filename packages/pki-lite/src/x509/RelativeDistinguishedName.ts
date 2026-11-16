import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { Asn1Node, PkiSet, UniversalTag } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a relative distinguished name (RDN).
 *
 * @asn
 * ```asn
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 * ```
 */
export class RelativeDistinguishedName extends PkiSet<AttributeTypeAndValue> {
    /**
     * Creates a RelativeDistinguishedName from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A RelativeDistinguishedName
     */
    static fromAsn1(asn1: Asn1Node): RelativeDistinguishedName {
        if (!asn1.is(UniversalTag.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SET but got ' +
                    asn1.describe(),
            )
        }

        const rdn = new RelativeDistinguishedName()

        for (const atvAsn1 of asn1.children) {
            const atv = AttributeTypeAndValue.fromAsn1(atvAsn1)
            rdn.push(atv)
        }

        return rdn
    }

    /**
     * Whether this RDN matches another (RFC 5280 7.1): the same set of attributes, each
     * matching as {@link AttributeTypeAndValue.matches} describes, in any order.
     */
    matches(other: RelativeDistinguishedName): boolean {
        return (
            this.length === other.length &&
            this.every((a) => other.some((b) => a.matches(b))) &&
            other.every((b) => this.some((a) => a.matches(b)))
        )
    }

    static parse(humanString: string): RelativeDistinguishedName {
        const atvStrings = humanString.split('+').map((s) => s.trim())
        const rdn = new RelativeDistinguishedName()

        for (const atvString of atvStrings) {
            const atv = AttributeTypeAndValue.parse(atvString)
            rdn.push(atv)
        }

        return rdn
    }
}
