import { Asn1Node, Choice, der, TagClass } from '../../core/PkiBase.js'
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
    fromAsn1: (asn1: Asn1Node): RecipientInfo => {
        // kari [1], kekri [2], pwri [3] and ori [4] are IMPLICIT: the SEQUENCE's
        // children sit directly in the context tag. Put the universal SEQUENCE tag back
        // so the individual parsers can read them.
        if (asn1.tagClass === TagClass.Context) {
            const sequence = der.sequence(asn1.children)
            switch (asn1.tag) {
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
                        `Unsupported RecipientInfo tag: ${asn1.tag}`,
                    )
            }
        }

        // Default to KeyTransRecipientInfo
        return KeyTransRecipientInfo.fromAsn1(asn1)
    },
    toAsn1: (value: RecipientInfo): Asn1Node => {
        let asn1 = value.toAsn1()

        // Add appropriate tags for non-KeyTransRecipientInfo types
        if (value instanceof KeyAgreeRecipientInfo) {
            asn1 = asn1.implicit(1) // [1] IMPLICIT
        } else if (value instanceof KEKRecipientInfo) {
            asn1 = asn1.implicit(2) // [2] IMPLICIT
        } else if (value instanceof PasswordRecipientInfo) {
            asn1 = asn1.implicit(3) // [3] IMPLICIT
        } else if (value instanceof OtherRecipientInfo) {
            asn1 = asn1.implicit(4) // [4] IMPLICIT
        }

        return asn1
    },
})
