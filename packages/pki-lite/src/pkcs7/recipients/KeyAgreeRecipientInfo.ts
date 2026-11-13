import {
    Asn1Node,
    der,
    PkiBase,
    PkiSet,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OriginatorIdentifierOrKey } from './OriginatorIdentifierOrKey.js'
import { RecipientEncryptedKey } from './RecipientEncryptedKey.js'
import { CMSVersion } from '../CMSVersion.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a collection of RecipientEncryptedKey structures.
 */
export class RecipientEncryptedKeys extends PkiSet<RecipientEncryptedKey> {
    static fromAsn1(asn1: Asn1Node): RecipientEncryptedKeys {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for RecipientEncryptedKeys',
            )
        }

        const recipientEncryptedKeys = asn1.children.map((keyAsn1) =>
            RecipientEncryptedKey.fromAsn1(keyAsn1),
        )

        return new RecipientEncryptedKeys(...recipientEncryptedKeys)
    }

    toAsn1(): Asn1Node {
        return der.sequence(this.map((key) => key.toAsn1()))
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
    ukm?: Uint8Array<ArrayBuffer>
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
        ukm?: Uint8Array<ArrayBuffer>
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
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [
            der.integer(this.version),
            der.constructed(0, [
                OriginatorIdentifierOrKey.toAsn1(this.originator),
            ]),
        ]

        // Add ukm if present
        if (this.ukm) {
            values.push(der.constructed(1, [der.octetString(this.ukm)]))
        }

        // Add keyEncryptionAlgorithm and recipientEncryptedKeys
        values.push(
            this.keyEncryptionAlgorithm.toAsn1(),
            this.recipientEncryptedKeys.toAsn1(),
        )

        return der.sequence(values)
    }

    /**
     * Creates a KeyAgreeRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): KeyAgreeRecipientInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KeyAgreeRecipientInfo',
            )
        }

        const values = asn1.children
        if (values.length < 4 || values.length > 5) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 4-5 elements, got ${values.length}`,
            )
        }

        // Check version
        if (!values[0]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = der.readNumber(values[0])
        if (version !== 3) {
            throw new Asn1ParseError(
                `Invalid version: expected 3, got ${version}`,
            )
        }

        // Extract originator
        if (
            !values[1]?.constructed ||
            values[1].tagClass !== TagClass.Context ||
            values[1].tag !== 0
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected [0] for originator',
            )
        }

        const originatorAsn1 = values[1].children[0]
        const originator = OriginatorIdentifierOrKey.fromAsn1(originatorAsn1)

        // Check for ukm (optional)
        let ukm: Uint8Array<ArrayBuffer> | undefined = undefined
        let currentIndex = 2

        if (
            values.length > 4 &&
            values[currentIndex]?.constructed &&
            values[currentIndex].tagClass === TagClass.Context &&
            values[currentIndex].tag === 1
        ) {
            const ukmAsn1 = values[currentIndex].children[0]
            if (!ukmAsn1.is(UniversalTag.OctetString)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected OctetString for ukm',
                )
            }

            ukm = ukmAsn1.bytes()
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
