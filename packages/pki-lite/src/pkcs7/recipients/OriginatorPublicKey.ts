import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
/**
 * Represents a OriginatorPublicKey structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * OriginatorPublicKey ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   publicKey BIT STRING }
 * ```
 */
export class OriginatorPublicKey extends PkiBase<OriginatorPublicKey> {
    algorithm: AlgorithmIdentifier
    publicKey: Uint8Array

    constructor(options: {
        algorithm: AlgorithmIdentifier
        publicKey: Uint8Array
    }) {
        super()
        this.algorithm = options.algorithm
        this.publicKey = options.publicKey
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.algorithm.toAsn1(),
                new asn1js.BitString({ valueHex: this.publicKey }),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): OriginatorPublicKey {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OriginatorPublicKey',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        const algorithm = AlgorithmIdentifier.fromAsn1(values[0])

        if (!(values[1] instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BitString for publicKey',
            )
        }

        const publicKey = new Uint8Array(values[1].valueBlock.valueHexView)

        return new OriginatorPublicKey({
            algorithm,
            publicKey,
        })
    }
}
