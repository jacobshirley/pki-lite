import { Asn1Node, PkiSet, UniversalTag } from '../core/PkiBase.js'
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
    static fromAsn1(asn1: Asn1Node): Attributes {
        if (!asn1.is(UniversalTag.Set) && !asn1?.constructed) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SET/CONSTRUCTED for Attributes but got ' +
                    asn1.describe(),
            )
        }

        const attributes = asn1.children.map((attrAsn1) =>
            Attribute.fromAsn1(attrAsn1),
        )

        return new Attributes(...attributes)
    }
}
