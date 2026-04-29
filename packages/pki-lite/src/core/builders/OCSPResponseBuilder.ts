import { OCSPResponse } from '../../ocsp/OCSPResponse.js'
import { BasicOCSPResponse } from '../../ocsp/BasicOCSPResponse.js'
import { ResponseData } from '../../ocsp/ResponseData.js'
import { SingleResponse } from '../../ocsp/SingleResponse.js'
import { ResponderID } from '../../ocsp/ResponderID.js'
import { ResponseBytes } from '../../ocsp/ResponseBytes.js'
import { OCSPResponseStatus } from '../../ocsp/OCSPResponseStatus.js'
import { CertID } from '../../ocsp/CertID.js'
import { CertStatus } from '../../ocsp/CertStatus.js'
import { Extension } from '../../x509/Extension.js'
import { Certificate } from '../../x509/Certificate.js'
import { Name } from '../../x509/Name.js'
import { OctetString } from '../../asn1/OctetString.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import {
    AlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { AsymmetricEncryptionAlgorithmParams } from '../crypto/types.js'
import { OIDs } from '../OIDs.js'
import { AsyncBuilder } from './types.js'

/** Default OCSP response validity: 7 days */
const DEFAULT_VALIDITY_MS = 7 * 24 * 60 * 60 * 1000

interface CertificateResponseData {
    issuerCertificate?: Certificate
    certificate?: Certificate
    certID?: CertID
    status: 'good' | 'revoked' | 'unknown'
    thisUpdate?: Date
    nextUpdate?: Date
    revocationTime?: Date
    revocationReason?: number
    singleExtensions?: Extension[]
}

/**
 * Builder class for creating OCSP Responses.
 *
 * Provides a fluent API for constructing OCSP responses with multiple certificate
 * statuses, responder identification, extensions, and signatures.
 *
 * @example
 * ```typescript
 * const response = await OCSPResponse.builder()
 *     .setResponderByName('CN=OCSP Responder')
 *     .setPrivateKey(responderKey)
 *     .addResponse(issuerCert, cert1, 'good')
 *     .addResponse(issuerCert, cert2, 'revoked', {
 *         revocationTime: new Date(),
 *         revocationReason: 0
 *     })
 *     .build()
 * ```
 */
export class OCSPResponseBuilder implements AsyncBuilder<OCSPResponse> {
    private responderID?: ResponderID
    private privateKey?: PrivateKeyInfo
    private producedAt?: Date
    private responseData: CertificateResponseData[] = []
    private responseExtensions: Extension[] = []
    private certificates: Certificate[] = []
    private responseStatus: OCSPResponseStatus | number =
        OCSPResponseStatus.successful
    private algorithm?:
        | AsymmetricEncryptionAlgorithmParams
        | SignatureAlgorithmIdentifier

    /**
     * Sets the responder ID using a name (byName).
     *
     * @param name The responder's distinguished name
     * @returns This builder for chaining
     */
    setResponderByName(name: string | Name): this {
        this.responderID = typeof name === 'string' ? Name.parse(name) : name
        return this
    }

    /**
     * Sets the responder ID from a certificate's subject.
     *
     * @param certificate The responder's certificate
     * @returns This builder for chaining
     */
    setResponderFromCertificate(certificate: Certificate): this {
        this.responderID = certificate.tbsCertificate.subject
        return this
    }

    /**
     * Sets the responder ID using a key hash (byKey).
     *
     * @param keyHash SHA-1 hash of the responder's public key
     * @returns This builder for chaining
     */
    setResponderByKeyHash(keyHash: Uint8Array<ArrayBuffer>): this {
        this.responderID = new OctetString({ bytes: keyHash })
        return this
    }

    /**
     * Sets the private key for signing the response.
     *
     * @param privateKey The responder's private key
     * @returns This builder for chaining
     */
    setPrivateKey(privateKey: PrivateKeyInfo): this {
        this.privateKey = privateKey
        return this
    }

    /**
     * Sets the producedAt time (when this response was generated).
     * Defaults to current time if not set.
     *
     * @param date The production date
     * @returns This builder for chaining
     */
    setProducedAt(date: Date): this {
        this.producedAt = date
        return this
    }

    /**
     * Adds a single certificate response.
     *
     * @param options Certificate response details
     * @returns This builder for chaining
     */
    addCertificateResponse(options: {
        issuerCertificate?: Certificate
        certificate?: Certificate
        certID?: CertID
        status: 'good' | 'revoked' | 'unknown'
        thisUpdate?: Date
        nextUpdate?: Date
        revocationTime?: Date
        revocationReason?: number
        singleExtensions?: Extension[]
    }): this {
        if (!options.certificate && !options.certID) {
            throw new Error('Either certificate or certID must be provided')
        }
        if (options.certificate && options.certID) {
            throw new Error('Cannot provide both certificate and certID')
        }
        if (options.certificate && !options.issuerCertificate) {
            throw new Error(
                'issuerCertificate is required when using Certificate objects',
            )
        }

        this.responseData.push(options)
        return this
    }

    /**
     * Helper method to create a CertID from issuer and subject certificates.
     *
     * @param issuerCertificate The issuer certificate
     * @param subjectCertificate The subject certificate
     * @returns Promise resolving to the CertID
     */
    private async createCertID(
        issuerCertificate: Certificate,
        subjectCertificate: Certificate,
    ): Promise<CertID> {
        return CertID.forCertificate(issuerCertificate, subjectCertificate)
    }

    /**
     * Converts stored response data to SingleResponse objects.
     * This is called at build time to create CertIDs from certificates.
     */
    private async buildSingleResponses(): Promise<SingleResponse[]> {
        const responses: SingleResponse[] = []

        for (const data of this.responseData) {
            // Resolve certID
            let certID: CertID
            if (data.certID) {
                certID = data.certID
            } else if (data.certificate && data.issuerCertificate) {
                certID = await this.createCertID(
                    data.issuerCertificate,
                    data.certificate,
                )
            } else {
                throw new Error(
                    'Invalid response data: missing certID and certificate',
                )
            }

            // Create cert status
            const certStatus =
                data.status === 'good'
                    ? CertStatus.createGood()
                    : data.status === 'revoked'
                      ? CertStatus.createRevoked(
                            data.revocationTime ?? new Date(),
                            data.revocationReason,
                        )
                      : CertStatus.createUnknown()

            const thisUpdate = data.thisUpdate ?? new Date()

            responses.push(
                new SingleResponse({
                    certID,
                    certStatus,
                    thisUpdate,
                    nextUpdate:
                        data.nextUpdate ??
                        new Date(thisUpdate.getTime() + DEFAULT_VALIDITY_MS),
                    singleExtensions: data.singleExtensions,
                }),
            )
        }

        return responses
    }

    /**
     * Adds a certificate status response.
     *
     * @param issuerOrCertID The issuer certificate (when using Certificate) or CertID directly
     * @param certificateOrStatus The subject certificate (when using Certificate) or status (when using CertID)
     * @param statusOrOptions The status (when using Certificate) or options (when using CertID)
     * @param options Optional parameters (only when using Certificate)
     * @returns This builder for chaining
     * @example
     * ```typescript
     * // With certificates
     * builder
     *   .addResponse(issuerCert, cert1, 'good')
     *   .addResponse(issuerCert, cert2, 'revoked', {
     *     revocationTime: new Date(),
     *     revocationReason: 0
     *   })
     *
     * // With CertID
     * builder.addResponse(certID, 'good')
     * ```
     */
    addResponse(
        issuerOrCertID: Certificate | CertID,
        certificateOrStatus: Certificate | 'good' | 'revoked' | 'unknown',
        statusOrOptions?:
            | 'good'
            | 'revoked'
            | 'unknown'
            | {
                  revocationTime?: Date
                  revocationReason?: number
                  thisUpdate?: Date
                  nextUpdate?: Date
                  singleExtensions?: Extension[]
              },
        options?: {
            revocationTime?: Date
            revocationReason?: number
            thisUpdate?: Date
            nextUpdate?: Date
            singleExtensions?: Extension[]
        },
    ): this {
        // Pattern 1: addResponse(issuerCert, subjectCert, status, options?)
        if (
            issuerOrCertID instanceof Certificate &&
            certificateOrStatus instanceof Certificate
        ) {
            const status = statusOrOptions as
                | 'good'
                | 'revoked'
                | 'unknown'
                | undefined
            if (!status) {
                throw new Error(
                    'Status is required when using Certificate objects',
                )
            }
            return this.addCertificateResponse({
                issuerCertificate: issuerOrCertID,
                certificate: certificateOrStatus,
                status,
                ...options,
            })
        }
        // Pattern 2: addResponse(certID, status, options?)
        else if (issuerOrCertID instanceof CertID) {
            const status = certificateOrStatus as 'good' | 'revoked' | 'unknown'
            const opts = statusOrOptions as
                | {
                      revocationTime?: Date
                      revocationReason?: number
                      thisUpdate?: Date
                      nextUpdate?: Date
                      singleExtensions?: Extension[]
                  }
                | undefined
            return this.addCertificateResponse({
                certID: issuerOrCertID,
                status,
                ...opts,
            })
        } else {
            throw new Error(
                'Invalid arguments: expected (issuerCert, subjectCert, status, options?) or (certID, status, options?)',
            )
        }
    }

    /**
     * Adds a response extension (applies to the entire response).
     *
     * @param extension The extension to add
     * @returns This builder for chaining
     */
    addResponseExtension(extension: Extension): this {
        this.responseExtensions.push(extension)
        return this
    }

    /**
     * Adds a certificate to include in the response (for chain validation).
     *
     * @param certificate The certificate to include
     * @returns This builder for chaining
     */
    addCertificate(certificate: Certificate): this {
        this.certificates.push(certificate)
        return this
    }

    /**
     * Sets the overall response status.
     *
     * @param status The OCSP response status
     * @returns This builder for chaining
     */
    setResponseStatus(status: OCSPResponseStatus | number): this {
        this.responseStatus = status
        return this
    }

    /**
     * Sets the signature algorithm.
     *
     * @param algorithm Algorithm parameters or SignatureAlgorithmIdentifier
     * @returns This builder for chaining
     */
    setAlgorithm(
        algorithm:
            | AsymmetricEncryptionAlgorithmParams
            | SignatureAlgorithmIdentifier,
    ): this {
        this.algorithm = algorithm
        return this
    }

    private validate(): void {
        // For error responses, we don't need responder info or responses
        if (
            this.responseStatus !== OCSPResponseStatus.successful &&
            typeof this.responseStatus !== 'object'
        ) {
            return
        }

        if (!this.responderID) {
            throw new Error('Responder ID is required')
        }
        if (!this.privateKey) {
            throw new Error('Private key is required for signing')
        }
        if (this.responseData.length === 0) {
            throw new Error('At least one certificate response is required')
        }
    }

    /**
     * Builds and signs the OCSP response.
     *
     * @returns Promise resolving to the signed OCSPResponse
     */
    async build(): Promise<OCSPResponse> {
        this.validate()

        // Handle error responses (no response bytes)
        if (
            this.responseStatus !== OCSPResponseStatus.successful &&
            typeof this.responseStatus !== 'object'
        ) {
            return new OCSPResponse({
                responseStatus: this.responseStatus,
            })
        }

        const signatureAlgorithm =
            this.algorithm instanceof SignatureAlgorithmIdentifier
                ? this.algorithm
                : AlgorithmIdentifier.signatureAlgorithm(
                      this.algorithm ?? {
                          type: 'RSASSA_PKCS1_v1_5',
                          params: { hash: 'SHA-256' },
                      },
                  )

        // Build single responses (this is where CertIDs are created from certificates)
        const singleResponses = await this.buildSingleResponses()

        const tbsResponseData = new ResponseData({
            responderID: this.responderID!,
            producedAt: this.producedAt ?? new Date(),
            responses: singleResponses,
            responseExtensions:
                this.responseExtensions.length > 0
                    ? this.responseExtensions
                    : undefined,
        })

        const signature = await signatureAlgorithm.sign(
            tbsResponseData,
            this.privateKey!,
        )

        const basicResponse = new BasicOCSPResponse({
            tbsResponseData,
            signatureAlgorithm,
            signature,
            certs: this.certificates.length > 0 ? this.certificates : undefined,
        })

        return new OCSPResponse({
            responseStatus: this.responseStatus,
            responseBytes: new ResponseBytes({
                responseType: OIDs.PKIX.ID_PKIX_OCSP_BASIC,
                response: basicResponse,
            }),
        })
    }
}
