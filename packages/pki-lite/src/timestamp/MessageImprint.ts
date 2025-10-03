import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * MessageImprint structure for RFC 3161 Time-Stamp Protocol.
 *
 * MessageImprint contains the hash of the data to be time-stamped along with
 * the algorithm used to compute the hash. This ensures the integrity of the
 * timestamped data by binding the timestamp to a specific hash value.
 *
 * @asn
 * ```asn
 * MessageImprint ::= SEQUENCE {
 *   hashAlgorithm     AlgorithmIdentifier,
 *   hashedMessage     OCTET STRING
 * }
 * ```
 *
 * @see RFC 3161 Section 2.4.1 - TSAReq Structure
 */
export class MessageImprint extends PkiBase<MessageImprint> {
    /** Algorithm used to hash the message */
    hashAlgorithm: AlgorithmIdentifier

    /** The hash value of the message to be timestamped */
    hashedMessage: Uint8Array<ArrayBuffer>

    /**
     * Creates a new MessageImprint instance.
     *
     * @param options Configuration object
     * @param options.hashAlgorithm The hash algorithm identifier
     * @param options.hashedMessage The computed hash value
     *
     * @example
     * ```typescript
     * const messageImprint = new MessageImprint({
     *     hashAlgorithm: AlgorithmIdentifier.hashAlgorithm({ type: 'SHA-256' }),
     *     hashedMessage: hashBytes
     * })
     * ```
     */
    constructor(options: {
        hashAlgorithm: AlgorithmIdentifier
        hashedMessage: Uint8Array<ArrayBuffer>
    }) {
        super()

        const { hashAlgorithm, hashedMessage } = options

        this.hashAlgorithm = hashAlgorithm
        this.hashedMessage = hashedMessage
    }

    /**
     * Converts the MessageImprint to its ASN.1 representation.
     *
     * @returns ASN.1 SEQUENCE containing the hash algorithm and hashed message
     *
     * @example
     * ```typescript
     * const asn1 = messageImprint.toAsn1()
     * const der = asn1.toBER(false)
     * ```
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.hashAlgorithm.toAsn1(),
                new asn1js.OctetString({
                    valueHex: this.hashedMessage,
                }),
            ],
        })
    }

    /**
     * Creates a MessageImprint from an ASN.1 structure.
     *
     * Parses the ASN.1 SEQUENCE and extracts the hash algorithm and hashed message.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed MessageImprint object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     *
     * @example
     * ```typescript
     * const asn1 = derToAsn1(messageImprintBytes)
     * const messageImprint = MessageImprint.fromAsn1(asn1)
     *
     * console.log(messageImprint.hashAlgorithm.algorithm) // Hash algorithm OID
     * console.log(messageImprint.hashedMessage) // Hash bytes
     * ```
     */
    static fromAsn1(asn1: Asn1BaseBlock): MessageImprint {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.valueBlock.value.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected exactly 2 elements',
            )
        }

        const hashAlgorithm = AlgorithmIdentifier.fromAsn1(
            asn1.valueBlock.value[0],
        )

        if (!(asn1.valueBlock.value[1] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OCTET STRING for hashedMessage',
            )
        }
        const hashedMessage = new Uint8Array(
            (
                asn1.valueBlock.value[1] as asn1js.OctetString
            ).valueBlock.valueHexView,
        )

        return new MessageImprint({
            hashAlgorithm,
            hashedMessage,
        })
    }
}
