import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { CMSVersion } from '../CMSVersion.js'
import { KEKIdentifier } from './KEKIdentifier.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a KEKRecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * KEKRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,  -- always set to 4
 *   kekid KEKIdentifier,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 * ```
 */
export class KEKRecipientInfo extends PkiBase<KEKRecipientInfo> {
    static KEKIdentifier = KEKIdentifier

    version: CMSVersion
    kekid: KEKIdentifier
    keyEncryptionAlgorithm: AlgorithmIdentifier
    encryptedKey: Uint8Array

    /**
     * Creates a new KEKRecipientInfo instance.
     */
    constructor(options: {
        kekid: KEKIdentifier
        keyEncryptionAlgorithm: AlgorithmIdentifier
        encryptedKey: Uint8Array
    }) {
        super()

        const { kekid, keyEncryptionAlgorithm, encryptedKey } = options

        this.version = CMSVersion.v4 // Always set to 4 per RFC 5652
        this.kekid = kekid
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        this.encryptedKey = encryptedKey
    }

    /**
     * Converts the KEKRecipientInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: this.version }),
                this.kekid.toAsn1(),
                this.keyEncryptionAlgorithm.toAsn1(),
                new asn1js.OctetString({ valueHex: this.encryptedKey }),
            ],
        })
    }

    /**
     * Creates a KEKRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): KEKRecipientInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KEKRecipientInfo',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 4 elements, got ${values.length}`,
            )
        }

        // Check version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }

        const version = values[0].valueBlock.valueDec
        if (version !== CMSVersion.v4) {
            throw new Asn1ParseError(
                `Invalid version: expected 4, got ${version}`,
            )
        }

        // Extract kekid
        const kekid = KEKIdentifier.fromAsn1(values[1])

        // Extract keyEncryptionAlgorithm
        const keyEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(values[2])

        // Extract encryptedKey
        if (!(values[3] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }
        const encryptedKey = new Uint8Array(values[3].valueBlock.valueHexView)

        return new KEKRecipientInfo({
            kekid,
            keyEncryptionAlgorithm,
            encryptedKey,
        })
    }
}
