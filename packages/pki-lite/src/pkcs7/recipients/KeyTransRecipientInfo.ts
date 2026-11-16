import {
    Asn1Node,
    Choice,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
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
    fromAsn1: (asn1: Asn1Node): RecipientIdentifier => {
        if (asn1.tagClass === TagClass.Context && asn1.tag === 0) {
            return SubjectKeyIdentifier.fromAsn1(asn1)
        }
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
    toAsn1: (value: RecipientIdentifier): Asn1Node => {
        let asn1 = value.toAsn1()

        if (value instanceof SubjectKeyIdentifier) {
            asn1 = asn1.implicit(0) // [0] IMPLICIT
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
    encryptedKey: Uint8Array<ArrayBuffer>

    /**
     * Creates a new KeyTransRecipientInfo instance.
     */
    constructor(options: {
        version?: CMSVersion
        rid: RecipientIdentifier
        keyEncryptionAlgorithm: AlgorithmIdentifier
        encryptedKey: Uint8Array<ArrayBuffer>
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
    static fromAsn1(asn1: Asn1Node): KeyTransRecipientInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KeyTransRecipientInfo',
            )
        }

        const values = asn1.children
        if (values.length !== 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 4 elements, got ${values.length}`,
            )
        }

        // Version
        if (!values[0]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }

        const version = der.readNumber(values[0])

        // RecipientIdentifier
        let rid: RecipientIdentifier = RecipientIdentifier.fromAsn1(values[1])

        // KeyEncryptionAlgorithm
        const keyEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(values[2])

        // EncryptedKey
        if (!values[3]?.is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }
        const encryptedKey = values[3].bytes()

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
    toAsn1(): Asn1Node {
        return der.sequence([
            der.integer(this.version),
            RecipientIdentifier.toAsn1(this.rid),
            this.keyEncryptionAlgorithm.toAsn1(),
            der.octetString(this.encryptedKey),
        ])
    }
}
