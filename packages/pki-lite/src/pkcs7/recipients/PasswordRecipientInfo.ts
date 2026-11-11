import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { CMSVersion } from '../CMSVersion.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag } from '../../core/tagging.js'

/**
 * Represents a PasswordRecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * PasswordRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,   -- always set to 0
 *   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 * ```
 */
export class PasswordRecipientInfo extends PkiBase<PasswordRecipientInfo> {
    version: CMSVersion
    keyDerivationAlgorithm?: AlgorithmIdentifier
    keyEncryptionAlgorithm: AlgorithmIdentifier
    encryptedKey: Uint8Array<ArrayBuffer>

    /**
     * Creates a new PasswordRecipientInfo instance.
     */
    constructor(options: {
        version?: CMSVersion
        keyEncryptionAlgorithm: AlgorithmIdentifier
        encryptedKey: Uint8Array<ArrayBuffer>
        keyDerivationAlgorithm?: AlgorithmIdentifier
    }) {
        super()

        const {
            version,
            keyEncryptionAlgorithm,
            encryptedKey,
            keyDerivationAlgorithm,
        } = options

        this.version = version ?? 0
        this.keyDerivationAlgorithm = keyDerivationAlgorithm
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        this.encryptedKey = encryptedKey
    }

    /**
     * Converts the PasswordRecipientInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values: asn1js.BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
        ]

        // keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier: the algorithm's
        // OID and parameters sit directly inside the [0]
        if (this.keyDerivationAlgorithm) {
            values.push(implicitTag(this.keyDerivationAlgorithm.toAsn1(), 0))
        }

        // Add keyEncryptionAlgorithm and encryptedKey
        values.push(
            this.keyEncryptionAlgorithm.toAsn1(),
            new asn1js.OctetString({ valueHex: this.encryptedKey }),
        )

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a PasswordRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): PasswordRecipientInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for PasswordRecipientInfo',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 3 || values.length > 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 3-4 elements, got ${values.length}`,
            )
        }

        // Check version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = values[0].valueBlock.valueDec
        if (version !== CMSVersion.v0) {
            throw new Asn1ParseError(
                `Invalid version: expected 0, got ${version}`,
            )
        }

        let currentIndex = 1
        let keyDerivationAlgorithm: AlgorithmIdentifier | undefined = undefined

        // Check for keyDerivationAlgorithm (optional)
        if (
            values.length > 3 &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 &&
            values[currentIndex].idBlock.tagNumber === 0
        ) {
            const constructed = values[currentIndex] as asn1js.Constructed
            const [first] = constructed.valueBlock.value
            // Earlier versions of this library wrapped the SEQUENCE in an explicit [0]
            keyDerivationAlgorithm = AlgorithmIdentifier.fromAsn1(
                constructed.valueBlock.value.length === 1 &&
                    first instanceof asn1js.Sequence
                    ? first
                    : // [0] IMPLICIT AlgorithmIdentifier: its fields are the children
                      new asn1js.Sequence({
                          value: constructed.valueBlock.value,
                      }),
            )
            currentIndex++
        }

        // Extract keyEncryptionAlgorithm
        const keyEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(
            values[currentIndex],
        )
        currentIndex++

        // Extract encryptedKey
        if (!(values[currentIndex] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for encryptedKey',
            )
        }

        const octetString = values[currentIndex] as asn1js.OctetString
        const encryptedKey = new Uint8Array(octetString.valueBlock.valueHexView)

        return new PasswordRecipientInfo({
            version,
            keyEncryptionAlgorithm,
            encryptedKey,
            keyDerivationAlgorithm,
        })
    }
}
