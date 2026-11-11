import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { AttributeCertificateInfo } from './AttributeCertificateInfo.js'
import { BitString } from '../../asn1/BitString.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an AttributeCertificate structure as defined in RFC 5755.
 *
 * @asn
 * ```asn
 * AttributeCertificate ::= SEQUENCE {
 *     acInfo               AttributeCertificateInfo,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING
 * }
 * ```
 */
export class AttributeCertificate extends PkiBase<AttributeCertificate> {
    acInfo: AttributeCertificateInfo
    signatureAlgorithm: AlgorithmIdentifier
    signatureValue: BitString

    /**
     * Creates a new AttributeCertificate instance.
     *
     * @param options The options object containing the certificate information
     */
    constructor(options: {
        acInfo: AttributeCertificateInfo
        signatureAlgorithm: AlgorithmIdentifier
        signatureValue: Uint8Array<ArrayBuffer> | BitString
    }) {
        super()
        const { acInfo, signatureAlgorithm, signatureValue } = options
        this.acInfo = acInfo
        this.signatureAlgorithm = signatureAlgorithm
        this.signatureValue = new BitString({ value: signatureValue })
    }

    /**
     * Converts the AttributeCertificate to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        return der.sequence([
            this.acInfo.toAsn1(),
            this.signatureAlgorithm.toAsn1(),
            this.signatureValue.toAsn1(),
        ])
    }

    /**
     * Creates an AttributeCertificate from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttributeCertificate
     */
    static fromAsn1(asn1: Asn1Node): AttributeCertificate {
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
        const acInfo = AttributeCertificateInfo.fromAsn1(values[0])

        // Extract signatureAlgorithm
        if (!values[1]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
            )
        }
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[1])

        // Extract signatureValue
        if (!values[2]?.is(UniversalTag.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING for signatureValue',
            )
        }
        const signatureValue = der.readBitString(values[2]).bytes

        return new AttributeCertificate({
            acInfo,
            signatureAlgorithm,
            signatureValue,
        })
    }
}
