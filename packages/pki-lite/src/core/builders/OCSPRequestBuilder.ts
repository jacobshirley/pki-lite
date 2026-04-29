import { OCSPRequest } from '../../ocsp/OCSPRequest.js'
import { TBSRequest } from '../../ocsp/TBSRequest.js'
import { Request } from '../../ocsp/Request.js'
import { CertID } from '../../ocsp/CertID.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../../x509/Certificate.js'
import { Name } from '../../x509/Name.js'
import { Extension } from '../../x509/Extension.js'
import { HashAlgorithm } from '../crypto/types.js'
import { AsyncBuilder } from './types.js'

/**
 * Builder class for creating OCSP (Online Certificate Status Protocol) requests.
 *
 * Provides a fluent API for constructing OCSP requests with one or more
 * certificate status queries.
 *
 * @example
 * ```typescript
 * // Single certificate check
 * const request = await OCSPRequest.builder()
 *     .addCertificate({
 *         certificate: clientCert,
 *         issuerCertificate: caCert,
 *     })
 *     .build()
 *
 * // Multiple certificates with custom hash algorithm
 * const request = await OCSPRequest.builder()
 *     .setHashAlgorithm('SHA-1')
 *     .addCertificate({ certificate: cert1, issuerCertificate: caCert })
 *     .addCertificate({ certificate: cert2, issuerCertificate: caCert })
 *     .build()
 *
 * const response = await request.request({ url: 'http://ocsp.example.com' })
 * ```
 */
export class OCSPRequestBuilder implements AsyncBuilder<OCSPRequest> {
    private version: number = 0
    private requestorName?: Name
    private hashAlgorithm: HashAlgorithm = 'SHA-256'
    private pendingCertificates: Array<{
        certificate: Certificate
        issuerCertificate: Certificate
        singleRequestExtensions?: Extension[]
    }> = []
    private requests: Request[] = []
    private requestExtensions: Extension[] = []

    /**
     * Sets the hash algorithm used to compute issuer name and key hashes
     * in CertID. Defaults to 'SHA-256'.
     *
     * Note: many OCSP responders only support SHA-1.
     *
     * @param hash The hash algorithm
     * @returns This builder for chaining
     */
    setHashAlgorithm(hash: HashAlgorithm): this {
        this.hashAlgorithm = hash
        return this
    }

    /**
     * Adds a certificate to be checked against its issuer.
     * The issuer name and key hashes will be computed automatically.
     *
     * @param options Certificate and its issuer
     * @returns This builder for chaining
     */
    addCertificate(options: {
        certificate: Certificate
        issuerCertificate: Certificate
        singleRequestExtensions?: Extension[]
    }): this {
        this.pendingCertificates.push(options)
        return this
    }

    /**
     * Adds a pre-built Request entry.
     *
     * @param request The Request to add
     * @returns This builder for chaining
     */
    addRequest(request: Request): this {
        this.requests.push(request)
        return this
    }

    /**
     * Sets the requestor's distinguished name (optional).
     *
     * @param name Requestor name as string or Name object
     * @returns This builder for chaining
     */
    setRequestorName(name: string | Name): this {
        this.requestorName = typeof name === 'string' ? Name.parse(name) : name
        return this
    }

    /**
     * Adds a request-level extension (e.g., nonce).
     *
     * @param extension The extension to add
     * @returns This builder for chaining
     */
    addExtension(extension: Extension): this {
        this.requestExtensions.push(extension)
        return this
    }

    /**
     * Sets the protocol version. Defaults to 0 (v1).
     *
     * @param version The protocol version
     * @returns This builder for chaining
     */
    setVersion(version: number): this {
        this.version = version
        return this
    }

    /**
     * Builds the OCSP request, computing CertIDs for all pending certificates.
     *
     * @returns Promise resolving to the OCSPRequest
     */
    async build(): Promise<OCSPRequest> {
        const hashAlgorithm = AlgorithmIdentifier.digestAlgorithm(
            this.hashAlgorithm,
        )

        const builtRequests: Request[] = [...this.requests]
        for (const entry of this.pendingCertificates) {
            const { certificate, issuerCertificate, singleRequestExtensions } =
                entry
            const certID = new CertID({
                hashAlgorithm,
                issuerNameHash: await hashAlgorithm.digest(
                    issuerCertificate.tbsCertificate.subject.toDer(),
                ),
                issuerKeyHash: await hashAlgorithm.digest(
                    issuerCertificate.getSubjectPublicKeyInfo()
                        .subjectPublicKey,
                ),
                serialNumber: certificate.tbsCertificate.serialNumber,
            })
            builtRequests.push(
                new Request({
                    reqCert: certID,
                    singleRequestExtensions,
                }),
            )
        }

        if (builtRequests.length === 0) {
            throw new Error('At least one certificate or request is required')
        }

        const tbsRequest = new TBSRequest({
            version: this.version,
            requestorName: this.requestorName,
            requestList: builtRequests,
            requestExtensions:
                this.requestExtensions.length > 0
                    ? this.requestExtensions
                    : undefined,
        })

        return new OCSPRequest({ tbsRequest })
    }
}
