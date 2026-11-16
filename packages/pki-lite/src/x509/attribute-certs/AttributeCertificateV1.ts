import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
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
    toAsn1(): Asn1Node {
        return der.sequence([
            this.acInfo.toAsn1(),
            this.signatureAlgorithm.toAsn1(),
            this.signature.toAsn1(),
        ])
    }

    /**
     * Creates an AttributeCertificateV1 from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttributeCertificateV1
     */
    static fromAsn1(asn1: Asn1Node): AttributeCertificateV1 {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.children
        if (values.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        // Extract acInfo
        if (!values[0]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for acInfo',
            )
        }
        const acInfo = AttributeCertificateInfoV1.fromAsn1(values[0])

        // Extract signatureAlgorithm
        if (!values[1]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
            )
        }
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[1])

        // Extract signature
        if (!values[2]?.is(UniversalTag.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING for signature',
            )
        }
        const signature = der.readBitString(values[2]).bytes

        return new AttributeCertificateV1({
            acInfo,
            signatureAlgorithm,
            signature,
        })
    }
}
