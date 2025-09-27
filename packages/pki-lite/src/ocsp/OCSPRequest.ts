import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { TBSRequest } from './TBSRequest.js'
import { OCSPSignature } from './OCSPSignature.js'
import { OCSPResponse } from './OCSPResponse.js'
import { Certificate } from '../x509/Certificate.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an OCSP (Online Certificate Status Protocol) request.
 *
 * An OCSP request is used to check the revocation status of X.509 certificates
 * in real-time. It can request the status of one or more certificates and
 * optionally include a signature to authenticate the requestor.
 *
 * @asn
 * ```asn
 * OCSPRequest ::= SEQUENCE {
 *     tbsRequest              TBSRequest,
 *     optionalSignature   [0] EXPLICIT Signature OPTIONAL
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Create OCSP request for a certificate
 * const request = await OCSPRequest.forCertificate({
 *     certificate: clientCert,
 *     issuerCertificate: caCert
 * })
 *
 * // Send to OCSP responder
 * const response = await fetch('http://ocsp.example.com', {
 *     method: 'POST',
 *     body: request.toDer(),
 *     headers: { 'Content-Type': 'application/ocsp-request' }
 * })
 *
 * // Parse response
 * const ocspResponse = OCSPResponse.fromDer(new Uint8Array(await response.arrayBuffer()))
 * ```
 */
export class OCSPRequest extends PkiBase<OCSPRequest> {
    /**
     * The "to be signed" request containing the certificate status queries.
     */
    tbsRequest: TBSRequest

    /**
     * Optional signature to authenticate the requestor.
     */
    optionalSignature?: OCSPSignature

    /**
     * Creates a new OCSPRequest instance.
     *
     * @param options Configuration object
     * @param options.tbsRequest The TBSRequest structure
     * @param options.optionalSignature Optional signature for authentication
     */
    constructor(options: {
        tbsRequest: TBSRequest
        optionalSignature?: OCSPSignature
    }) {
        super()
        this.tbsRequest = options.tbsRequest
        this.optionalSignature = options.optionalSignature
    }

    /**
     * Creates an OCSP request for checking a specific certificate's status.
     *
     * @param options Configuration object
     * @param options.certificate The certificate to check
     * @param options.issuerCertificate The issuer's certificate
     * @returns A new OCSPRequest instance
     */
    static async forCertificate(options: {
        certificate: Certificate
        issuerCertificate: Certificate
    }): Promise<OCSPRequest> {
        const tbsRequest = await TBSRequest.forCertificate(options)
        return new OCSPRequest({ tbsRequest })
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [this.tbsRequest.toAsn1()]

        if (this.optionalSignature) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [this.optionalSignature.toAsn1()],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): OCSPRequest {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (
            sequence.valueBlock.value.length < 1 ||
            sequence.valueBlock.value.length > 2
        ) {
            throw new Asn1ParseError(
                'Invalid OCSPRequest: expected 1 or 2 elements',
            )
        }

        const tbsRequest = TBSRequest.fromAsn1(sequence.valueBlock.value[0])
        let optionalSignature: OCSPSignature | undefined = undefined

        if (sequence.valueBlock.value.length === 2) {
            const signatureContainer = sequence.valueBlock
                .value[1] as asn1js.Constructed
            if (
                signatureContainer.idBlock.tagClass !== 3 ||
                signatureContainer.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid OCSPRequest: expected [0] tag for optionalSignature',
                )
            }

            optionalSignature = OCSPSignature.fromAsn1(
                signatureContainer.valueBlock.value[0],
            )
        }

        return new OCSPRequest({
            tbsRequest,
            optionalSignature,
        })
    }

    static fromDer(der: Uint8Array): OCSPRequest {
        return OCSPRequest.fromAsn1(derToAsn1(der))
    }

    async request(options: { url: string }): Promise<OCSPResponse> {
        const res = await fetch(options.url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/ocsp-request',
                Accept: 'application/ocsp-response',
            },
            body: this.toDer(),
        })

        if (!res.ok) {
            throw new Error(
                `OCSP request failed with status ${res.status} [${res.statusText}]: ${await res.text()}`,
            )
        }

        if (res.status >= 300) {
            throw new Error(
                `OCSP request failed with status ${res.status} [${res.statusText}]: ${await res.text()}`,
            )
        }

        const responseDer = new Uint8Array(await res.arrayBuffer())
        return OCSPResponse.fromDer(responseDer)
    }
}
