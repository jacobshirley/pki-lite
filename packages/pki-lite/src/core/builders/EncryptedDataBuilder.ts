import { EncryptedData } from '../../pkcs7/EncryptedData.js'
import { EncryptedContentInfo } from '../../pkcs7/EncryptedContentInfo.js'
import {
    AlgorithmIdentifier,
    ContentEncryptionAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { SymmetricEncryptionAlgorithmParams } from '../crypto/types.js'
import { AsyncBuilder } from './types.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { ObjectIdentifierString } from '../PkiBase.js'
import { CONTENT_TYPE_TO_OID, Pkcs7ContentType } from '../OIDs.js'

/**
 * Builder class for creating PKCS#7 EncryptedData structures.
 *
 * Provides a fluent API for encrypting data. By default uses PBES2 (PBKDF2 + AES-256-CBC),
 * but can accept custom algorithms via setAlgorithm().
 *
 * @example
 * ```typescript
 * // Using default PBES2 algorithm
 * const encryptedData = await EncryptedData.builder()
 *     .setContentType('DATA')
 *     .setData(contentBytes)
 *     .setPassword('secret')
 *     .setIterations(2048)
 *     .build()
 *
 * // Using custom algorithm
 * const customEncrypted = await EncryptedData.builder()
 *     .setContentType('DATA')
 *     .setData(contentBytes)
 *     .setPassword('secret')
 *     .setAlgorithm({
 *         type: 'AES_256_GCM',
 *         params: { nonce: randomIV }
 *     })
 *     .build()
 * ```
 */
export class EncryptedDataBuilder implements AsyncBuilder<EncryptedData> {
    private contentType?: ObjectIdentifier
    private data?: Uint8Array<ArrayBuffer>
    private password?: string | Uint8Array<ArrayBuffer>
    private salt?: Uint8Array<ArrayBuffer>
    private iv?: Uint8Array<ArrayBuffer>
    private iterations: number = 2048
    private algorithm?:
        | SymmetricEncryptionAlgorithmParams
        | ContentEncryptionAlgorithmIdentifier

    /**
     * Sets the content type OID for the encrypted data.
     *
     * @param contentType The content type OID
     * @returns This builder for chaining
     */
    setContentTypeOid(type: ObjectIdentifier | ObjectIdentifierString): this {
        this.contentType = new ObjectIdentifier({ value: type })
        return this
    }

    /**
     * Sets the content type using a friendly name.
     *
     * @param type The content type name
     * @returns This builder for chaining
     */
    setContentType(type: Pkcs7ContentType): this {
        this.contentType = new ObjectIdentifier({
            value: CONTENT_TYPE_TO_OID[type],
        })
        return this
    }

    /**
     * Sets the data to encrypt.
     *
     * @param data The data bytes
     * @returns This builder for chaining
     */
    setData(data: Uint8Array<ArrayBuffer>): this {
        this.data = data
        return this
    }

    /**
     * Sets the password for encryption.
     *
     * @param password The password (string or bytes)
     * @returns This builder for chaining
     */
    setPassword(password: string | Uint8Array<ArrayBuffer>): this {
        this.password = password
        return this
    }

    /**
     * Sets the salt for PBKDF2. If not set, a random salt will be generated.
     *
     * @param salt The salt bytes
     * @returns This builder for chaining
     */
    setSalt(salt: Uint8Array<ArrayBuffer>): this {
        this.salt = salt
        return this
    }

    /**
     * Sets the IV for AES encryption. If not set, a random IV will be generated.
     *
     * @param iv The IV bytes
     * @returns This builder for chaining
     */
    setIV(iv: Uint8Array<ArrayBuffer>): this {
        this.iv = iv
        return this
    }

    /**
     * Sets the iteration count for PBKDF2. Defaults to 2048.
     *
     * @param iterations The iteration count
     * @returns This builder for chaining
     */
    setIterations(iterations: number): this {
        this.iterations = iterations
        return this
    }

    /**
     * Sets the encryption algorithm. Accepts either algorithm parameters or a pre-built algorithm identifier.
     * If not set, defaults to PBES2 (PBKDF2 + AES-256-CBC).
     *
     * @param algorithm The encryption algorithm parameters or identifier
     * @returns This builder for chaining
     */
    setAlgorithm(
        algorithm:
            | SymmetricEncryptionAlgorithmParams
            | ContentEncryptionAlgorithmIdentifier,
    ): this {
        this.algorithm = algorithm
        return this
    }

    private validate(): void {
        if (!this.contentType) {
            throw new Error('Content type is required')
        }
        if (!this.data) {
            throw new Error('Data is required')
        }
        if (!this.password) {
            throw new Error('Password is required')
        }
    }

    /**
     * Builds the EncryptedData structure.
     *
     * @returns Promise resolving to the EncryptedData instance
     */
    async build(): Promise<EncryptedData> {
        this.validate()

        let encryptionAlgorithm: ContentEncryptionAlgorithmIdentifier

        // Use custom algorithm if provided
        if (this.algorithm) {
            if (
                this.algorithm instanceof ContentEncryptionAlgorithmIdentifier
            ) {
                encryptionAlgorithm = this.algorithm
            } else {
                encryptionAlgorithm =
                    AlgorithmIdentifier.contentEncryptionAlgorithm(
                        this.algorithm,
                    )
            }
        } else {
            // Default to PBES2 (PBKDF2 + AES-256-CBC)
            const salt = this.salt ?? crypto.getRandomValues(new Uint8Array(16))
            const iv = this.iv ?? crypto.getRandomValues(new Uint8Array(16))

            encryptionAlgorithm =
                AlgorithmIdentifier.contentEncryptionAlgorithm({
                    type: 'PBES2',
                    params: {
                        derivationAlgorithm: {
                            type: 'PBKDF2',
                            params: {
                                salt,
                                iterationCount: this.iterations,
                                hash: 'SHA-256',
                            },
                        },
                        encryptionAlgorithm: {
                            type: 'AES_256_CBC',
                            params: { nonce: iv },
                        },
                    },
                })
        }

        const ciphertext = await encryptionAlgorithm.encrypt(
            this.data!,
            this.password!,
        )

        return new EncryptedData({
            version: 0,
            encryptedContentInfo: new EncryptedContentInfo({
                contentType: this.contentType!,
                contentEncryptionAlgorithm: encryptionAlgorithm,
                encryptedContent: ciphertext,
            }),
        })
    }
}
