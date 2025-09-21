import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a MessageImprint from RFC 3161.
 *
 * @asn
 * ```asn
 * MessageImprint ::= SEQUENCE  {
 *      hashAlgorithm                AlgorithmIdentifier,
 *      hashedMessage                OCTET STRING
 * }
 * ```
 */
export class MessageImprint extends PkiBase<MessageImprint> {
    hashAlgorithm: AlgorithmIdentifier
    hashedMessage: Uint8Array

    constructor(options: {
        hashAlgorithm: AlgorithmIdentifier
        hashedMessage: Uint8Array
    }) {
        super()

        const { hashAlgorithm, hashedMessage } = options

        this.hashAlgorithm = hashAlgorithm
        this.hashedMessage = hashedMessage
    }

    /**
     * Converts the MessageImprint to an ASN.1 structure.
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
     * @param asn1 The ASN.1 structure
     * @returns A MessageImprint
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
