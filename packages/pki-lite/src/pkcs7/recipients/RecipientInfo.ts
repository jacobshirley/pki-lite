import { Asn1BaseBlock, Choice } from '../../core/PkiBase.js'
import { KeyTransRecipientInfo } from './KeyTransRecipientInfo.js'
import { KeyAgreeRecipientInfo } from './KeyAgreeRecipientInfo.js'
import { KEKRecipientInfo } from './KEKRecipientInfo.js'
import { PasswordRecipientInfo } from './PasswordRecipientInfo.js'
import { OtherRecipientInfo } from './OtherRecipientInfo.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

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
        // Check if it's a tagged type
        if (asn1.idBlock.tagClass === 3) {
            switch (asn1.idBlock.tagNumber) {
                case 1:
                    return KeyAgreeRecipientInfo.fromAsn1(asn1)
                case 2:
                    return KEKRecipientInfo.fromAsn1(asn1)
                case 3:
                    return PasswordRecipientInfo.fromAsn1(asn1)
                case 4:
                    return OtherRecipientInfo.fromAsn1(asn1)
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
