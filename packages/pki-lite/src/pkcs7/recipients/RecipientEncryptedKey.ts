import {
    Asn1Node,
    Choice,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
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
    fromAsn1: (asn1: Asn1Node): KeyAgreeRecipientIdentifier => {
        // If it's a context-specific tag
        if (asn1?.constructed && asn1.tagClass === TagClass.Context) {
            const tagNumber = asn1.tag

            // rKeyId [0]
            if (tagNumber === 0) {
                return RecipientKeyIdentifier.fromAsn1(asn1.children[0])
            }

            throw new Asn1ParseError(`Unsupported tag number: ${tagNumber}`)
        }

        // Default to IssuerAndSerialNumber
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
    toAsn1: (value: KeyAgreeRecipientIdentifier): Asn1Node => {
        let asn1 = value.toAsn1()
        if (value instanceof RecipientKeyIdentifier) {
            asn1 = asn1.implicit(0) // [0] IMPLICIT
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

    toAsn1(): Asn1Node {
        const ridAsn1 = KeyAgreeRecipientIdentifier.toAsn1(this.rid)

        return der.sequence([ridAsn1, der.octetString(this.encryptedKey)])
    }

    static fromAsn1(asn1: Asn1Node): RecipientEncryptedKey {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for RecipientEncryptedKey',
            )
        }

        const values = asn1.children
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        let rid: KeyAgreeRecipientIdentifier

        // Check if it's a RecipientKeyIdentifier (with [0] tag)
        if (
            values[0]?.constructed &&
            values[0].tagClass === TagClass.Context &&
            values[0].tag === 0
        ) {
            rid = RecipientKeyIdentifier.fromAsn1(values[0].children[0])
        } else {
            // Otherwise it's an IssuerAndSerialNumber
            rid = IssuerAndSerialNumber.fromAsn1(values[0])
        }

        if (!values[1]?.is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }

        const encryptedKey = values[1].bytes()

        return new RecipientEncryptedKey({ rid, encryptedKey })
    }
}
