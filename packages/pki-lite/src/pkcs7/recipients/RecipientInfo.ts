import { Asn1BaseBlock, Choice } from '../../core/PkiBase.js'
import { KeyTransRecipientInfo } from './KeyTransRecipientInfo.js'
import { KeyAgreeRecipientInfo } from './KeyAgreeRecipientInfo.js'
import { KEKRecipientInfo } from './KEKRecipientInfo.js'
import { PasswordRecipientInfo } from './PasswordRecipientInfo.js'
import { OtherRecipientInfo } from './OtherRecipientInfo.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { withUniversalTag } from '../../core/tagging.js'

/**
 * Represents a CMS RecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * RecipientInfo ::= CHOICE {
 *   ktri KeyTransRecipientInfo,
 *   kari [1] KeyAgreeRecipientInfo,
 *   kekri [2] KEKRecipientInfo,
 *   pwri [3] PasswordRecipientInfo,
 *   ori [4] OtherRecipientInfo
 * }
 * ```
 */
export type RecipientInfo =
    | KeyTransRecipientInfo
    | KeyAgreeRecipientInfo
    | KEKRecipientInfo
    | PasswordRecipientInfo
    | OtherRecipientInfo

export const RecipientInfo = Choice('RecipientInfo', {
    KeyTransRecipientInfo,
    KeyAgreeRecipientInfo,
    KEKRecipientInfo,
    PasswordRecipientInfo,
    OtherRecipientInfo,
    fromAsn1: (asn1: Asn1BaseBlock): RecipientInfo => {
        // kari [1], kekri [2], pwri [3] and ori [4] are IMPLICIT: the SEQUENCE's
        // children sit directly in the context tag. Put the universal SEQUENCE tag back
        // so the individual parsers can read them.
        if (asn1.idBlock.tagClass === 3) {
            const sequence = withUniversalTag(asn1, 16)
            switch (asn1.idBlock.tagNumber) {
                case 1:
                    return KeyAgreeRecipientInfo.fromAsn1(sequence)
                case 2:
                    return KEKRecipientInfo.fromAsn1(sequence)
                case 3:
                    return PasswordRecipientInfo.fromAsn1(sequence)
                case 4:
                    return OtherRecipientInfo.fromAsn1(sequence)
                default:
                    throw new Asn1ParseError(
                        `Unsupported RecipientInfo tag: ${asn1.idBlock.tagNumber}`,
                    )
            }
        }

        // Default to KeyTransRecipientInfo
        return KeyTransRecipientInfo.fromAsn1(asn1)
    },
    toAsn1: (value: RecipientInfo): Asn1BaseBlock => {
        const asn1 = value.toAsn1()

        // Add appropriate tags for non-KeyTransRecipientInfo types
        if (value instanceof KeyAgreeRecipientInfo) {
            asn1.idBlock.tagClass = 3
            asn1.idBlock.tagNumber = 1
        } else if (value instanceof KEKRecipientInfo) {
            asn1.idBlock.tagClass = 3
            asn1.idBlock.tagNumber = 2
        } else if (value instanceof PasswordRecipientInfo) {
            asn1.idBlock.tagClass = 3
            asn1.idBlock.tagNumber = 3
        } else if (value instanceof OtherRecipientInfo) {
            asn1.idBlock.tagClass = 3
            asn1.idBlock.tagNumber = 4
        }

        return asn1
    },
})
