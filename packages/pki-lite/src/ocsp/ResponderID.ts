import { Asn1BaseBlock, Choice, asn1js } from '../core/PkiBase.js'
import { Name } from '../x509/Name.js'
import { OctetString } from '../asn1/OctetString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 *
 * @asn
 *
 * ```asn
 * KeyHash ::= OCTET STRING -- SHA-1 hash of responder's key
 * ```
 */
export const KeyHash = OctetString
export type KeyHash = OctetString

/**
 * Represents the SHA-1 hash of the responder's key.
 *
 * @asn
 *
 * ```asn
 * ResponderID ::= CHOICE {
 *     byName              [1] Name,
 *     byKey               [2] KeyHash
 * }
 * ```
 */
export type ResponderID = Name | KeyHash
export const ResponderID = Choice('ResponderID', {
    byName: Name,
    byKey: KeyHash,
    fromAsn1: (asn1: Asn1BaseBlock): ResponderID => {
        if (asn1 instanceof asn1js.Constructed) {
            const tagNumber = asn1.idBlock.tagNumber
            if (tagNumber === 1) {
                return ResponderID.byName.fromAsn1(asn1.valueBlock.value[0])
            } else if (tagNumber === 2) {
                return ResponderID.byKey.fromAsn1(asn1.valueBlock.value[0])
            }
        }
        throw new Asn1ParseError('Invalid ASN.1 structure for ResponderID')
    },
    toAsn1: (value: ResponderID): Asn1BaseBlock => {
        if (value instanceof ResponderID.byKey) {
            return new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 2, // [2]
                },
                value: [value.toAsn1()],
            })
        } else {
            return new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 1, // [1]
                },
                value: [value.toAsn1()],
            })
        }
    },
})
