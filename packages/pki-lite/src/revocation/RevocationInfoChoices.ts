import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { Asn1BaseBlock, asn1js, PkiSet } from '../core/PkiBase.js'
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
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []
        for (const choice of this) {
            const asn1 = choice.toAsn1()

            if (choice instanceof OtherRevocationInfoFormat) {
                asn1.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
                asn1.idBlock.tagNumber = 1 // [1]
            }

            values.push(asn1)
        }
        return new asn1js.Set({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): RevocationInfoChoices {
        if (!(asn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for RevocationInfoChoices',
            )
        }

        const choices = asn1.valueBlock.value.map((choiceAsn1) =>
            RevocationInfoChoice.fromAsn1(choiceAsn1),
        )

        return new RevocationInfoChoices(...choices)
    }
}
