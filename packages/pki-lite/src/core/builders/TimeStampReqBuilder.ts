import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { TimeStampReq } from '../../timestamp/TimeStampReq.js'
import { MessageImprint } from '../../timestamp/MessageImprint.js'
import { Extension } from '../../x509/Extension.js'
import { ObjectIdentifierString } from '../PkiBase.js'
import { HashAlgorithm } from '../crypto/types.js'
import { AsyncBuilder } from './types.js'

/**
 * Builder class for creating RFC 3161 Time-Stamp Requests.
 *
 * Provides a fluent API for constructing TimeStampReq objects, including
 * automatic hashing of input data.
 *
 * @example
 * ```typescript
 * // Build from raw data (hash computed automatically)
 * const tsReq = await TimeStampReq.builder()
 *     .setData(documentBytes)
 *     .setHashAlgorithm('SHA-256')
 *     .setCertReq(true)
 *     .setNonce(crypto.getRandomValues(new Uint8Array(8)))
 *     .build()
 *
 * // Send to TSA
 * const response = await tsReq.request({ url: 'https://freetsa.org/tsr' })
 * ```
 */
export class TimeStampReqBuilder implements AsyncBuilder<TimeStampReq> {
    private version: number = 1
    private messageImprint?: MessageImprint
    private data?: Uint8Array<ArrayBuffer>
    private hashAlgorithm: HashAlgorithm = 'SHA-256'
    private reqPolicy?: ObjectIdentifierString
    private nonce?: Uint8Array<ArrayBuffer>
    private certReq: boolean = false
    private extensions: Extension[] = []

    /**
     * Sets the data to be timestamped. The hash will be computed automatically
     * during build() using the configured hash algorithm.
     *
     * @param data The data to timestamp (raw bytes or string)
     * @returns This builder for chaining
     */
    setData(data: Uint8Array<ArrayBuffer> | string): this {
        this.data =
            typeof data === 'string' ? new TextEncoder().encode(data) : data
        return this
    }

    /**
     * Sets a pre-computed message imprint, bypassing automatic hashing.
     *
     * @param messageImprint The message imprint
     * @returns This builder for chaining
     */
    setMessageImprint(messageImprint: MessageImprint): this {
        this.messageImprint = messageImprint
        return this
    }

    /**
     * Sets the hash algorithm used to compute the message imprint.
     * Only used when setData() is provided. Defaults to 'SHA-256'.
     *
     * @param hash The hash algorithm
     * @returns This builder for chaining
     */
    setHashAlgorithm(hash: HashAlgorithm): this {
        this.hashAlgorithm = hash
        return this
    }

    /**
     * Sets the requested TSA policy OID.
     *
     * @param policy The TSA policy identifier
     * @returns This builder for chaining
     */
    setReqPolicy(policy: ObjectIdentifierString): this {
        this.reqPolicy = policy
        return this
    }

    /**
     * Sets the nonce for replay protection.
     *
     * @param nonce The nonce bytes (typically 8-16 random bytes)
     * @returns This builder for chaining
     */
    setNonce(nonce: Uint8Array<ArrayBuffer>): this {
        this.nonce = nonce
        return this
    }

    /**
     * Generates and sets a random nonce for replay protection.
     *
     * @param byteLength The length of the random nonce (default 8)
     * @returns This builder for chaining
     */
    setRandomNonce(byteLength: number = 8): this {
        this.nonce = crypto.getRandomValues(new Uint8Array(byteLength))
        return this
    }

    /**
     * Sets whether to request the TSA certificate in the response.
     *
     * @param certReq Whether to request the TSA certificate
     * @returns This builder for chaining
     */
    setCertReq(certReq: boolean = true): this {
        this.certReq = certReq
        return this
    }

    /**
     * Adds a request extension.
     *
     * @param extension The extension to add
     * @returns This builder for chaining
     */
    addExtension(extension: Extension): this {
        this.extensions.push(extension)
        return this
    }

    /**
     * Sets the protocol version. Defaults to 1.
     *
     * @param version The protocol version
     * @returns This builder for chaining
     */
    setVersion(version: number): this {
        this.version = version
        return this
    }

    /**
     * Builds the timestamp request, computing the message imprint hash if
     * data was provided via setData().
     *
     * @returns Promise resolving to the TimeStampReq
     */
    async build(): Promise<TimeStampReq> {
        let messageImprint = this.messageImprint
        if (!messageImprint) {
            if (!this.data) {
                throw new Error(
                    'Either setData() or setMessageImprint() is required',
                )
            }
            const algorithm = AlgorithmIdentifier.digestAlgorithm(
                this.hashAlgorithm,
            )
            messageImprint = new MessageImprint({
                hashAlgorithm: algorithm,
                hashedMessage: await algorithm.digest(this.data),
            })
        }

        return new TimeStampReq({
            version: this.version,
            messageImprint,
            reqPolicy: this.reqPolicy,
            nonce: this.nonce,
            certReq: this.certReq,
            extensions:
                this.extensions.length > 0 ? this.extensions : undefined,
        })
    }
}
