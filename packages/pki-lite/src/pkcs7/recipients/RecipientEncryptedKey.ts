import { Asn1BaseBlock, asn1js, Choice, PkiBase } from '../../core/PkiBase.js'
import { KeyIdentifier } from './KeyIdentifier.js'
import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { RecipientKeyIdentifier } from './RecipientKeyIdentifier.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Type for KeyAgreeRecipientIdentifier as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * KeyAgreeRecipientIdentifier ::= CHOICE {
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   rKeyId [0] IMPLICIT RecipientKeyIdentifier
 * }
 * ```
 */
type KeyAgreeRecipientIdentifier =
    | IssuerAndSerialNumber
    | RecipientKeyIdentifier

const KeyAgreeRecipientIdentifier = Choice('KeyAgreeRecipientIdentifier', {
    IssuerAndSerialNumber,
    RecipientKeyIdentifier,
    fromAsn1: (asn1: Asn1BaseBlock): KeyAgreeRecipientIdentifier => {
        // If it's a context-specific tag
        if (asn1 instanceof asn1js.Constructed && asn1.idBlock.tagClass === 3) {
            const tagNumber = asn1.idBlock.tagNumber

            // rKeyId [0]
            if (tagNumber === 0) {
                return RecipientKeyIdentifier.fromAsn1(asn1.valueBlock.value[0])
            }

            throw new Asn1ParseError(`Unsupported tag number: ${tagNumber}`)
        }

        // Default to IssuerAndSerialNumber
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
    toAsn1: (value: KeyAgreeRecipientIdentifier): Asn1BaseBlock => {
        const asn1 = value.toAsn1()
        if (value instanceof RecipientKeyIdentifier) {
            asn1.idBlock.tagClass = 3 // Context-specific
            asn1.idBlock.tagNumber = 0
        } else if (!(value instanceof IssuerAndSerialNumber)) {
            throw new Asn1ParseError(`Unsupported type: ${value}`)
        }

        return asn1
    },
})

/**
 * Represents a RecipientEncryptedKey structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * RecipientEncryptedKey ::= SEQUENCE {
 *   rid KeyAgreeRecipientIdentifier,
 *   encryptedKey EncryptedKey }
 *
 * EncryptedKey ::= OCTET STRING
 * ```
 */
export class RecipientEncryptedKey extends PkiBase<RecipientEncryptedKey> {
    static KeyAgreeRecipientIdentifier = KeyAgreeRecipientIdentifier

    rid: KeyAgreeRecipientIdentifier
    encryptedKey: Uint8Array<ArrayBuffer>

    constructor(options: {
        rid: KeyAgreeRecipientIdentifier
        encryptedKey: Uint8Array<ArrayBuffer>
    }) {
        super()
        const { rid, encryptedKey } = options
        this.rid = rid
        this.encryptedKey = encryptedKey
    }

    toAsn1(): Asn1BaseBlock {
        const ridAsn1 = KeyAgreeRecipientIdentifier.toAsn1(this.rid)

        return new asn1js.Sequence({
            value: [
                ridAsn1,
                new asn1js.OctetString({ valueHex: this.encryptedKey }),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): RecipientEncryptedKey {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for RecipientEncryptedKey',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        let rid: KeyAgreeRecipientIdentifier

        // Check if it's a RecipientKeyIdentifier (with [0] tag)
        if (
            values[0] instanceof asn1js.Constructed &&
            values[0].idBlock.tagClass === 3 &&
            values[0].idBlock.tagNumber === 0
        ) {
            rid = RecipientKeyIdentifier.fromAsn1(values[0].valueBlock.value[0])
        } else {
            // Otherwise it's an IssuerAndSerialNumber
            rid = IssuerAndSerialNumber.fromAsn1(values[0])
        }

        if (!(values[1] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }

        const encryptedKey = new Uint8Array(values[1].valueBlock.valueHexView)

        return new RecipientEncryptedKey({ rid, encryptedKey })
    }
}
