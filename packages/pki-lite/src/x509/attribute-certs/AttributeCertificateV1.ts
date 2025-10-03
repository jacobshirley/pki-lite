import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { AttributeCertificateInfoV1 } from './AttributeCertificateInfoV1.js'
import { BitString } from '../../asn1/BitString.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an AttributeCertificateV1 structure which is marked as obsolete.
 *
 * @asn
 * ```asn
 * AttributeCertificateV1 ::= SEQUENCE {
 *     acInfo               AttributeCertificateInfoV1,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signature            BIT STRING
 * }
 * ```
 */
export class AttributeCertificateV1 extends PkiBase<AttributeCertificateV1> {
    acInfo: AttributeCertificateInfoV1
    signatureAlgorithm: AlgorithmIdentifier
    signature: BitString

    /**
     * Creates a new AttributeCertificateV1 instance.
     *
     * @param options The options object containing the certificate information
     */
    constructor(options: {
        acInfo: AttributeCertificateInfoV1
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array<ArrayBuffer> | BitString
    }) {
        super()
        const { acInfo, signatureAlgorithm, signature } = options
        this.acInfo = acInfo
        this.signatureAlgorithm = signatureAlgorithm
        this.signature = new BitString({ value: signature })
    }

    /**
     * Converts the AttributeCertificateV1 to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.acInfo.toAsn1(),
                this.signatureAlgorithm.toAsn1(),
                this.signature.toAsn1(),
            ],
        })
    }

    /**
     * Creates an AttributeCertificateV1 from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttributeCertificateV1
     */
    static fromAsn1(asn1: Asn1BaseBlock): AttributeCertificateV1 {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // Define a type for the valueBlock structure we need to access
        interface ValueBlock {
            value: asn1js.BaseBlock[]
        }

        const values = (asn1.valueBlock as unknown as ValueBlock).value
        if (values.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        // Extract acInfo
        if (!(values[0] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for acInfo',
            )
        }
        const acInfo = AttributeCertificateInfoV1.fromAsn1(values[0])

        // Extract signatureAlgorithm
        if (!(values[1] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
            )
        }
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[1])

        // Extract signature
        if (!(values[2] instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING for signature',
            )
        }
        const signature = new Uint8Array(values[2].valueBlock.valueHexView)

        return new AttributeCertificateV1({
            acInfo,
            signatureAlgorithm,
            signature,
        })
    }
}
