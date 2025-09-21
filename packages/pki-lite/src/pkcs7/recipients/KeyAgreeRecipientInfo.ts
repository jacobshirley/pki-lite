import { Asn1BaseBlock, asn1js, PkiBase, PkiSet } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OriginatorIdentifierOrKey } from './OriginatorIdentifierOrKey.js'
import { RecipientEncryptedKey } from './RecipientEncryptedKey.js'
import { CMSVersion } from '../CMSVersion.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a collection of RecipientEncryptedKey structures.
 */
export class RecipientEncryptedKeys extends PkiSet<RecipientEncryptedKey> {
    static fromAsn1(asn1: Asn1BaseBlock): RecipientEncryptedKeys {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for RecipientEncryptedKeys',
            )
        }

        const recipientEncryptedKeys = asn1.valueBlock.value.map((keyAsn1) =>
            RecipientEncryptedKey.fromAsn1(keyAsn1),
        )

        return new RecipientEncryptedKeys(...recipientEncryptedKeys)
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: this.map((key) => key.toAsn1()),
        })
    }
}

/**
 * Represents a KeyAgreeRecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * KeyAgreeRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,  -- always set to 3
 *   originator [0] EXPLICIT OriginatorIdentifierOrKey,
 *   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   recipientEncryptedKeys RecipientEncryptedKeys }
 *
 * RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
 * ```
 */
export class KeyAgreeRecipientInfo extends PkiBase<KeyAgreeRecipientInfo> {
    version: CMSVersion
    originator: OriginatorIdentifierOrKey
    ukm?: Uint8Array
    keyEncryptionAlgorithm: AlgorithmIdentifier
    recipientEncryptedKeys: RecipientEncryptedKeys

    /**
     * Creates a new KeyAgreeRecipientInfo instance.
     */
    constructor(options: {
        version: CMSVersion
        originator: OriginatorIdentifierOrKey
        keyEncryptionAlgorithm: AlgorithmIdentifier
        recipientEncryptedKeys: RecipientEncryptedKeys
        ukm?: Uint8Array
    }) {
        super()
        const {
            version,
            originator,
            keyEncryptionAlgorithm,
            recipientEncryptedKeys,
            ukm,
        } = options
        this.version = version
        this.originator = originator
        this.ukm = ukm
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        this.recipientEncryptedKeys = recipientEncryptedKeys
    }

    /**
     * Converts the KeyAgreeRecipientInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT_SPECIFIC
                    tagNumber: 0, // [0]
                },
                value: [OriginatorIdentifierOrKey.toAsn1(this.originator)],
            }),
        ]

        // Add ukm if present
        if (this.ukm) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT_SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    value: [new asn1js.OctetString({ valueHex: this.ukm })],
                }),
            )
        }

        // Add keyEncryptionAlgorithm and recipientEncryptedKeys
        values.push(
            this.keyEncryptionAlgorithm.toAsn1(),
            this.recipientEncryptedKeys.toAsn1(),
        )

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a KeyAgreeRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): KeyAgreeRecipientInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KeyAgreeRecipientInfo',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 4 || values.length > 5) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 4-5 elements, got ${values.length}`,
            )
        }

        // Check version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = values[0].valueBlock.valueDec
        if (version !== 3) {
            throw new Asn1ParseError(
                `Invalid version: expected 3, got ${version}`,
            )
        }

        // Extract originator
        if (
            !(values[1] instanceof asn1js.Constructed) ||
            values[1].idBlock.tagClass !== 3 ||
            values[1].idBlock.tagNumber !== 0
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected [0] for originator',
            )
        }

        const originatorAsn1 = values[1].valueBlock.value[0]
        const originator = OriginatorIdentifierOrKey.fromAsn1(originatorAsn1)

        // Check for ukm (optional)
        let ukm: Uint8Array | undefined = undefined
        let currentIndex = 2

        if (
            values.length > 4 &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 &&
            values[currentIndex].idBlock.tagNumber === 1
        ) {
            const ukmAsn1 = (values[currentIndex] as asn1js.Constructed)
                .valueBlock.value[0]
            if (!(ukmAsn1 instanceof asn1js.OctetString)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected OctetString for ukm',
                )
            }

            ukm = new Uint8Array(ukmAsn1.valueBlock.valueHexView)
            currentIndex++
        }

        // Extract keyEncryptionAlgorithm
        const keyEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(
            values[currentIndex],
        )
        currentIndex++

        // Extract recipientEncryptedKeys
        const recipientEncryptedKeys = RecipientEncryptedKeys.fromAsn1(
            values[currentIndex],
        )

        return new KeyAgreeRecipientInfo({
            version,
            originator,
            keyEncryptionAlgorithm,
            recipientEncryptedKeys,
            ukm,
        })
    }
}
