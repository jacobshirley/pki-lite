import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
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
    publicKey: Uint8Array<ArrayBuffer>

    constructor(options: {
        algorithm: AlgorithmIdentifier
        publicKey: Uint8Array<ArrayBuffer>
    }) {
        super()
        this.algorithm = options.algorithm
        this.publicKey = options.publicKey
    }

    toAsn1(): Asn1Node {
        return der.sequence([
            this.algorithm.toAsn1(),
            der.bitString(this.publicKey),
        ])
    }

    static fromAsn1(asn1: Asn1Node): OriginatorPublicKey {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OriginatorPublicKey',
            )
        }

        const values = asn1.children
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        const algorithm = AlgorithmIdentifier.fromAsn1(values[0])

        if (!values[1]?.is(UniversalTag.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BitString for publicKey',
            )
        }

        const publicKey = der.readBitString(values[1]).bytes

        return new OriginatorPublicKey({
            algorithm,
            publicKey,
        })
    }
}
