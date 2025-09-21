import { Asn1BaseBlock, asn1js, PkiSet } from '../core/PkiBase.js'
import { Attribute } from './Attribute.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of attributes.
 *
 * @asn
 * ```asn
 * Attributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
export class Attributes extends PkiSet<Attribute> {
    static fromAsn1(asn1: Asn1BaseBlock): Attributes {
        if (
            !(asn1 instanceof asn1js.Set) &&
            !(asn1 instanceof asn1js.Constructed)
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SET/CONSTRUCTED for Attributes but got ' +
                    asn1.constructor.name,
            )
        }

        const attributes = asn1.valueBlock.value.map((attrAsn1) =>
            Attribute.fromAsn1(attrAsn1),
        )

        return new Attributes(...attributes)
    }
}
