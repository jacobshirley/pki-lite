import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { Asn1Node, der, PkiSet, UniversalTag } from '../core/PkiBase.js'
import { RevocationInfoChoice } from './RevocationInfoChoice.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of revocation information choices.
 *
 * This class is used to group multiple revocation information structures.
 *
 * @asn
 * ```asn
 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
 * ```
 */
export class RevocationInfoChoices extends PkiSet<RevocationInfoChoice> {
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []
        for (const choice of this) {
            const asn1 = choice.toAsn1()
            // other [1] IMPLICIT OtherRevocationInfoFormat
            values.push(
                choice instanceof OtherRevocationInfoFormat
                    ? asn1.implicit(1)
                    : asn1,
            )
        }
        return der.set(values)
    }

    static fromAsn1(asn1: Asn1Node): RevocationInfoChoices {
        if (!asn1.is(UniversalTag.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for RevocationInfoChoices',
            )
        }

        const choices = asn1.children.map((choiceAsn1) =>
            RevocationInfoChoice.fromAsn1(choiceAsn1),
        )

        return new RevocationInfoChoices(...choices)
    }
}
