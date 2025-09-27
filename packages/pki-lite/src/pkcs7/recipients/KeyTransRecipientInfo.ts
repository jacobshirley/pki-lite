import { Asn1BaseBlock, asn1js, Choice, PkiBase } from '../../core/PkiBase.js'
import {
    AlgorithmIdentifier,
    KeyEncryptionAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { SubjectKeyIdentifier } from '../../keys/SubjectKeyIdentifier.js'
import { CMSVersion } from '../CMSVersion.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the identifier of a recipient in a KeyTransRecipientInfo structure.
 *
 * @asn
 * ```asn
 * RecipientIdentifier ::= CHOICE {
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   subjectKeyIdentifier [0] SubjectKeyIdentifier
 * }
 */
export type RecipientIdentifier = IssuerAndSerialNumber | SubjectKeyIdentifier

export const RecipientIdentifier = Choice('RecipientIdentifier', {
    IssuerAndSerialNumber,
    SubjectKeyIdentifier,
    fromAsn1: (asn1: Asn1BaseBlock): RecipientIdentifier => {
        if (asn1.idBlock.tagClass === 3 && asn1.idBlock.tagNumber === 0) {
            return SubjectKeyIdentifier.fromAsn1(asn1)
        }
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
    toAsn1: (value: RecipientIdentifier): Asn1BaseBlock => {
        const asn1 = value.toAsn1()

        if (value instanceof SubjectKeyIdentifier) {
            asn1.idBlock.tagClass = 3
            asn1.idBlock.tagNumber = 0
        }

        return asn1
    },
})

/**
 * Represents a KeyTransRecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * KeyTransRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,  -- always set to 0 or 2
 *   rid RecipientIdentifier,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey
 * }
 * ```
 */
export class KeyTransRecipientInfo extends PkiBase<KeyTransRecipientInfo> {
    /**
     * Version of the KeyTransRecipientInfo structure.
     * - 0: When issuerAndSerialNumber is used to identify the recipient
     * - 2: When subjectKeyIdentifier is used to identify the recipient
     */
    version: CMSVersion

    /**
     * Recipient identifier, either IssuerAndSerialNumber or SubjectKeyIdentifier.
     */
    rid: RecipientIdentifier

    /**
     * Algorithm used to encrypt the content-encryption key.
     */
    keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier

    /**
     * Encrypted content-encryption key.
     */
    encryptedKey: Uint8Array

    /**
     * Creates a new KeyTransRecipientInfo instance.
     */
    constructor(options: {
        version?: CMSVersion
        rid: RecipientIdentifier
        keyEncryptionAlgorithm: AlgorithmIdentifier
        encryptedKey: Uint8Array
    }) {
        super()
        const { version, rid, keyEncryptionAlgorithm, encryptedKey } = options

        this.rid = rid
        this.keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier(
            keyEncryptionAlgorithm,
        )
        this.encryptedKey = encryptedKey
        this.version = version ?? (rid instanceof SubjectKeyIdentifier ? 2 : 0)
    }

    /**
     * Creates a KeyTransRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): KeyTransRecipientInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KeyTransRecipientInfo',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 4 elements, got ${values.length}`,
            )
        }

        // Version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }

        const version = values[0].valueBlock.valueDec

        // RecipientIdentifier
        let rid: RecipientIdentifier = RecipientIdentifier.fromAsn1(values[1])

        // KeyEncryptionAlgorithm
        const keyEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(values[2])

        // EncryptedKey
        if (!(values[3] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }
        const encryptedKey = new Uint8Array(values[3].valueBlock.valueHexView)

        return new KeyTransRecipientInfo({
            version,
            rid,
            keyEncryptionAlgorithm,
            encryptedKey,
        })
    }

    /**
     * Converts the KeyTransRecipientInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: this.version }),
                RecipientIdentifier.toAsn1(this.rid),
                this.keyEncryptionAlgorithm.toAsn1(),
                new asn1js.OctetString({ valueHex: this.encryptedKey }),
            ],
        })
    }
}
