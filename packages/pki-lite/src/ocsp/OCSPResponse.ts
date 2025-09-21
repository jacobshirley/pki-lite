import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { OIDs } from '../core/OIDs.js'
import { ResponseBytes } from './ResponseBytes.js'
import { BasicOCSPResponse } from './BasicOCSPResponse.js'
import { OCSPResponseStatus } from './OCSPResponseStatus.js'
import { Certificate } from '../x509/Certificate.js'
import { ResponseData } from './ResponseData.js'
import { Name } from '../x509/Name.js'
import { AsymmetricEncryptionAlgorithmParams } from '../core/crypto/types.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { SingleResponse } from './SingleResponse.js'
import { CertID } from './CertID.js'
import { CertStatus } from './CertStatus.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

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

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [this.responseStatus.toAsn1()]

        if (this.responseBytes) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [this.responseBytes.toAsn1()],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): OCSPResponse {
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
                'Invalid OCSPResponse: expected 1 or 2 elements',
            )
        }

        const responseStatusBlock = sequence.valueBlock
            .value[0] as asn1js.Enumerated
        const responseStatus = responseStatusBlock.valueBlock.valueDec

        let responseBytes: ResponseBytes | undefined = undefined

        if (sequence.valueBlock.value.length === 2) {
            const responseBytesContainer = sequence.valueBlock
                .value[1] as asn1js.Constructed
            if (
                responseBytesContainer.idBlock.tagClass !== 3 ||
                responseBytesContainer.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid OCSPResponse: expected [0] tag for responseBytes',
                )
            }

            responseBytes = ResponseBytes.fromAsn1(
                responseBytesContainer.valueBlock.value[0],
            )
        }

        return new OCSPResponse({
            responseStatus,
            responseBytes,
        })
    }

    static fromDer(der: Uint8Array): OCSPResponse {
        return OCSPResponse.fromAsn1(derToAsn1(der))
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
        const signatureAlgorithmParams: AsymmetricEncryptionAlgorithmParams =
            options.signatureAlgorithmParams ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: {
                    hash: 'SHA-256',
                },
            }

        const signatureAlgorithm = AlgorithmIdentifier.signatureAlgorithm(
            signatureAlgorithmParams,
        )

        const hashAlgorithm = AlgorithmIdentifier.digestAlgorithm('SHA-256')

        const certId = new CertID({
            hashAlgorithm,
            issuerNameHash: await hashAlgorithm.digest(
                options.issuerCertificate.tbsCertificate.issuer.toDer(),
            ),
            issuerKeyHash: await hashAlgorithm.digest(
                options.issuerCertificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.toDer(),
            ),
            serialNumber:
                options.subjectCertificate.tbsCertificate.serialNumber,
        })

        const thisUpdate = options?.thisUpdate ?? new Date()

        const tbsResponseData = new ResponseData({
            responderID:
                options.responderID ??
                options.issuerCertificate.tbsCertificate.subject,
            producedAt: options?.productedAt ?? new Date(),
            responses: [
                new SingleResponse({
                    certID: certId,
                    certStatus: CertStatus.good,
                    thisUpdate,
                    nextUpdate:
                        options?.nextUpdate ??
                        new Date(
                            thisUpdate.getTime() + 7 * 24 * 60 * 60 * 1000, // +7 days
                        ),
                }),
            ],
        })

        const basicResponse = new BasicOCSPResponse({
            tbsResponseData,
            signatureAlgorithm,
            signature: await signatureAlgorithm.sign(
                tbsResponseData,
                options.privateKey,
            ),
        })

        return new OCSPResponse({
            responseStatus: OCSPResponseStatus.successful,
            responseBytes: new ResponseBytes({
                responseType: OIDs.PKIX.ID_PKIX_OCSP_BASIC,
                response: basicResponse,
            }),
        })
    }
}
