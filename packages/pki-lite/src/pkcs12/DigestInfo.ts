import { OctetString } from '../asn1/OctetString.js'
import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a DigestInfo structure in a PKCS#12 file.
 *
 * @asn
 * ```asn
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest OCTET STRING
 * }
 * ```
 */
export class DigestInfo extends PkiBase<DigestInfo> {
    digestAlgorithm: DigestAlgorithmIdentifier
    digest: OctetString

    constructor(options: {
        digestAlgorithm: AlgorithmIdentifier
        digest: OctetString | Uint8Array<ArrayBuffer>
    }) {
        super()
        this.digestAlgorithm = new DigestAlgorithmIdentifier(
            options.digestAlgorithm,
        )
        this.digest =
            options.digest instanceof OctetString
                ? options.digest
                : new OctetString({ bytes: options.digest })
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.digestAlgorithm.toAsn1(), this.digest.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): DigestInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('DigestInfo: expected SEQUENCE')
        }
        const [alg, dig] = asn1.valueBlock.value
        return new DigestInfo({
            digestAlgorithm: AlgorithmIdentifier.fromAsn1(alg),
            digest: OctetString.fromAsn1(dig),
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): DigestInfo {
        return DigestInfo.fromAsn1(derToAsn1(der))
    }
}
