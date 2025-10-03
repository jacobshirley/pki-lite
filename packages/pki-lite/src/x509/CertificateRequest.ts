import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { CertificateRequestInfo } from './CertificateRequestInfo.js'
import { BitString } from '../asn1/BitString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a PKCS#10 certificate request.
 *
 * @asn
 * ```asn
 * CertificationRequest ::= SEQUENCE {
 *      certificationRequestInfo CertificationRequestInfo,
 *      signatureAlgorithm       AlgorithmIdentifier,
 *      signature                BIT STRING
 * }
 * ```
 */
export class CertificateRequest extends PkiBase<CertificateRequest> {
    requestInfo: CertificateRequestInfo
    signatureAlgorithm: AlgorithmIdentifier
    signature: BitString

    constructor(options: {
        requestInfo: CertificateRequestInfo
        signatureAlgorithm: AlgorithmIdentifier
        signature: string | Uint8Array<ArrayBuffer> | BitString
    }) {
        super()

        this.requestInfo = options.requestInfo
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signature = new BitString({ value: options.signature })
    }

    /**
     * Converts the certificate request to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        // Create the main CertificateRequest sequence
        return new asn1js.Sequence({
            value: [
                this.requestInfo.toAsn1(),
                this.signatureAlgorithm.toAsn1(),
                this.signature.toAsn1(),
            ],
        })
    }

    /**
     * Creates a CertificateRequest from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A CertificateRequest
     */
    static fromAsn1(asn1: Asn1BaseBlock): CertificateRequest {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.valueBlock.value.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        const requestInfoAsn1 = asn1.valueBlock.value[0]
        const signatureAlgorithmAsn1 = asn1.valueBlock.value[1]
        const signatureAsn1 = asn1.valueBlock.value[2]

        if (!(requestInfoAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: requestInfo must be a SEQUENCE',
            )
        }

        if (!(signatureAlgorithmAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: signatureAlgorithm must be a SEQUENCE',
            )
        }

        if (!(signatureAsn1 instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: signature must be a BIT STRING',
            )
        }

        const requestInfo = CertificateRequestInfo.fromAsn1(requestInfoAsn1)
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            signatureAlgorithmAsn1,
        )

        const signature = new Uint8Array(signatureAsn1.valueBlock.valueHexView)

        return new CertificateRequest({
            requestInfo,
            signatureAlgorithm,
            signature,
        })
    }
}
