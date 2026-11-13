import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { ResponseBytes } from './ResponseBytes.js'
import { BasicOCSPResponse } from './BasicOCSPResponse.js'
import { OCSPResponseStatus } from './OCSPResponseStatus.js'
import { Certificate } from '../x509/Certificate.js'
import { Name } from '../x509/Name.js'
import { AsymmetricEncryptionAlgorithmParams } from '../core/crypto/types.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { CertID } from './CertID.js'
import { SingleResponse } from './SingleResponse.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OCSPResponseBuilder } from '../core/builders/OCSPResponseBuilder.js'

/**
 * Represents an OCSP (Online Certificate Status Protocol) Response.
 *
 * @asn
 * ```asn
 * OCSPResponse ::= SEQUENCE {
 *     responseStatus          OCSPResponseStatus,
 *     responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL
 * }
 *
 * ResponseBytes ::=       SEQUENCE {
 *     responseType   OBJECT IDENTIFIER,
 *     response       OCTET STRING
 * }
 * ```
 */
export class OCSPResponse extends PkiBase<OCSPResponse> {
    responseStatus: OCSPResponseStatus
    responseBytes?: ResponseBytes

    constructor(options: {
        responseStatus: OCSPResponseStatus | number
        responseBytes?: ResponseBytes
    }) {
        super()
        this.responseStatus = new OCSPResponseStatus(options.responseStatus)
        this.responseBytes = options.responseBytes
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [this.responseStatus.toAsn1()]

        if (this.responseBytes) {
            values.push(der.constructed(0, [this.responseBytes.toAsn1()]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): OCSPResponse {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length < 1 || sequence.children.length > 2) {
            throw new Asn1ParseError(
                'Invalid OCSPResponse: expected 1 or 2 elements',
            )
        }

        const responseStatusBlock = sequence.children[0]
        const responseStatus = der.readEnumerated(responseStatusBlock)

        let responseBytes: ResponseBytes | undefined = undefined

        if (sequence.children.length === 2) {
            const responseBytesContainer = sequence.children[1]
            if (
                responseBytesContainer.tagClass !== TagClass.Context ||
                responseBytesContainer.tag !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid OCSPResponse: expected [0] tag for responseBytes',
                )
            }

            responseBytes = ResponseBytes.fromAsn1(
                responseBytesContainer.children[0],
            )
        }

        return new OCSPResponse({
            responseStatus,
            responseBytes,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): OCSPResponse {
        return OCSPResponse.fromAsn1(derToAsn1(der))
    }

    /**
     * Whether the responder answered (responseStatus successful). Other statuses
     * (malformedRequest, tryLater, ...) carry no certificate status.
     */
    get isSuccessful(): boolean {
        return (
            this.responseStatus.value === 0 && this.responseBytes !== undefined
        )
    }

    /**
     * Verifies that a successful response comes from `issuer` or a responder it
     * authorised; see {@link BasicOCSPResponse.verify}.
     *
     * @example
     * ```typescript
     * const response = OCSPResponse.fromDer(der)
     * if (await response.verify(caCertificate)) {
     *     const single = await response.getResponse(certificate, caCertificate)
     *     if (single?.isCurrent()) console.log(single.certStatus.status)
     * }
     * ```
     */
    async verify(
        issuer: Certificate,
        options: { time?: Date } = {},
    ): Promise<boolean> {
        if (!this.isSuccessful) return false
        return this.getBasicOCSPResponse().verify(issuer, options)
    }

    /**
     * The status the response gives for `certificate`, issued by `issuer`: the single
     * response whose CertID identifies it, if any (none for an unsuccessful response).
     *
     * Does not check that the response is genuine or current: see {@link verify} and
     * {@link SingleResponse.isCurrent}.
     */
    async getResponse(
        certificate: Certificate,
        issuer: Certificate,
    ): Promise<SingleResponse | undefined> {
        if (!this.isSuccessful) return undefined
        for (const single of this.getBasicOCSPResponse().tbsResponseData
            .responses) {
            try {
                if (await single.certID.matches(certificate, issuer)) {
                    return single
                }
            } catch {
                // a hash algorithm that is not supported
            }
        }
        return undefined
    }

    /**
     * Parse the BasicOCSPResponse from the response bytes if available
     * and if the responseType is id-pkix-ocsp-basic
     */
    getBasicOCSPResponse(): BasicOCSPResponse {
        if (!this.responseBytes) {
            throw new Error('No responseBytes available in OCSPResponse')
        }

        if (this.responseBytes.responseType !== OIDs.PKIX.ID_PKIX_OCSP_BASIC) {
            throw new Asn1ParseError(
                'Invalid responseType: expected id-pkix-ocsp-basic',
            )
        }

        return this.responseBytes.response.parseAs(BasicOCSPResponse)
    }

    /**
     * Returns a builder for creating OCSP responses.
     *
     * @returns A new OCSPResponseBuilder instance
     */
    static builder(): OCSPResponseBuilder {
        return new OCSPResponseBuilder()
    }

    static async forCertificate(options: {
        issuerCertificate: Certificate
        subjectCertificate: Certificate
        privateKey: PrivateKeyInfo
        responderID?: Name
        productedAt?: Date
        signatureAlgorithmParams?: AsymmetricEncryptionAlgorithmParams
        thisUpdate?: Date
        nextUpdate?: Date
    }): Promise<OCSPResponse> {
        const certId = await CertID.forCertificate(
            options.issuerCertificate,
            options.subjectCertificate,
        )

        const builder = OCSPResponse.builder()
            .setPrivateKey(options.privateKey)
            .addResponse(certId, 'good', {
                thisUpdate: options.thisUpdate,
                nextUpdate: options.nextUpdate,
            })

        if (options.responderID) {
            builder.setResponderByName(options.responderID)
        } else {
            builder.setResponderFromCertificate(options.issuerCertificate)
        }

        if (options.productedAt) {
            builder.setProducedAt(options.productedAt)
        }

        if (options.signatureAlgorithmParams) {
            builder.setAlgorithm(options.signatureAlgorithmParams)
        }

        return builder.build()
    }
}
