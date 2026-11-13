import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { ExtendedCertificateInfo } from './ExtendedCertificateInfo.js'
import { BitString } from '../../asn1/BitString.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an ExtendedCertificate structure.
 *
 * This structure is marked as obsolete in the ASN.1 definition but is included for
 * compatibility with legacy systems.
 *
 * @asn
 * ```asn
 * ExtendedCertificate ::= SEQUENCE {
 *     extendedCertificateInfo ExtendedCertificateInfo,
 *     signatureAlgorithm AlgorithmIdentifier,
 *     signature BIT STRING
 * }
 * ```
 */
export class ExtendedCertificate extends PkiBase<ExtendedCertificate> {
    extendedCertificateInfo: ExtendedCertificateInfo
    signatureAlgorithm: AlgorithmIdentifier
    signature: BitString

    /**
     * Creates a new ExtendedCertificate instance.
     *
     * @param options The options object containing the certificate information
     */
    constructor(options: {
        extendedCertificateInfo: ExtendedCertificateInfo
        signatureAlgorithm: AlgorithmIdentifier
        signature: string | Uint8Array<ArrayBuffer> | BitString
    }) {
        super()
        const { extendedCertificateInfo, signatureAlgorithm, signature } =
            options
        this.extendedCertificateInfo = extendedCertificateInfo
        this.signatureAlgorithm = signatureAlgorithm
        this.signature = new BitString({ value: signature })
    }

    /**
     * Converts the ExtendedCertificate to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        return der.sequence([
            this.extendedCertificateInfo.toAsn1(),
            this.signatureAlgorithm.toAsn1(),
            this.signature.toAsn1(),
        ])
    }

    /**
     * Creates an ExtendedCertificate from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The ExtendedCertificate
     */
    static fromAsn1(asn1: Asn1Node): ExtendedCertificate {
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

        // Extract extendedCertificateInfo
        if (!values[0]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for extendedCertificateInfo',
            )
        }
        const extendedCertificateInfo = ExtendedCertificateInfo.fromAsn1(
            values[0],
        )

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

        return new ExtendedCertificate({
            extendedCertificateInfo,
            signatureAlgorithm,
            signature,
        })
    }
}
