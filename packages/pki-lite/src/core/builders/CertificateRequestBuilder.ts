import {
    AlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { CertificateRequest } from '../../x509/CertificateRequest.js'
import { CertificateRequestInfo } from '../../x509/CertificateRequestInfo.js'
import { Extension } from '../../x509/Extension.js'
import { Name } from '../../x509/Name.js'
import { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { AsyncBuilder } from './types.js'
import { AsymmetricEncryptionAlgorithmParams } from '../crypto/types.js'
import { KeyUsageOptions } from '../../x509/extensions/KeyUsage.js'
import { ExtKeyCommonNames } from '../../x509/extensions/ExtKeyUsage.js'
import { GeneralName } from '../../x509/GeneralName.js'
import { Attribute } from '../../x509/Attribute.js'
import { OIDs } from '../OIDs.js'
import { asn1js } from '../PkiBase.js'

/**
 * Builder class for creating PKCS#10 certificate signing requests (CSRs).
 *
 * This builder provides a fluent API for constructing CSRs with
 * various options including subject, extensions, and signature algorithm.
 *
 * @example
 * ```typescript
 * // Create a simple CSR
 * const csr = await CertificateRequest.builder()
 *     .setSubject('CN=example.com, O=My Org, C=US')
 *     .setPublicKey(publicKey)
 *     .setPrivateKey(privateKey)
 *     .addKeyUsage({ digitalSignature: true, keyEncipherment: true })
 *     .addSubjectAltName('example.com', '*.example.com')
 *     .build()
 * ```
 */
export class CertificateRequestBuilder
    implements AsyncBuilder<CertificateRequest>
{
    private subject?: Name
    private publicKey?: SubjectPublicKeyInfo
    private privateKey?: PrivateKeyInfo
    private extensions: Extension[] = []
    private algorithm?:
        | AsymmetricEncryptionAlgorithmParams
        | SignatureAlgorithmIdentifier
    private version: number = 0 // PKCS#10 v1

    /**
     * Sets the subject distinguished name for the CSR.
     *
     * @param subject Subject DN as string or Name object
     * @returns This builder for chaining
     */
    setSubject(subject: string | Name): this {
        this.subject =
            typeof subject === 'string' ? Name.parse(subject) : subject
        return this
    }

    /**
     * Sets the subject's public key.
     *
     * @param publicKey The subject's public key
     * @returns This builder for chaining
     */
    setPublicKey(publicKey: SubjectPublicKeyInfo): this {
        this.publicKey = publicKey
        return this
    }

    /**
     * Sets the private key for signing the CSR.
     *
     * @param privateKey The private key
     * @returns This builder for chaining
     */
    setPrivateKey(privateKey: PrivateKeyInfo): this {
        this.privateKey = privateKey
        return this
    }

    /**
     * Adds an extension to the CSR.
     * Extensions are included in the extensionRequest attribute.
     *
     * @param extension The extension to add
     * @returns This builder for chaining
     */
    addExtension(extension: Extension): this {
        this.extensions.push(extension)
        return this
    }

    /**
     * Adds multiple extensions to the CSR.
     *
     * @param extensions Array of extensions to add
     * @returns This builder for chaining
     */
    addExtensions(...extensions: Extension[]): this {
        this.extensions.push(...extensions)
        return this
    }

    /**
     * Adds a Key Usage extension to the CSR.
     *
     * @param options Key usage flags
     * @returns This builder for chaining
     * @example
     * ```typescript
     * builder.addKeyUsage({
     *     digitalSignature: true,
     *     keyEncipherment: true
     * })
     * ```
     */
    addKeyUsage(options: KeyUsageOptions): this {
        this.extensions.push(Extension.keyUsage(options))
        return this
    }

    /**
     * Adds a Subject Alternative Name extension to the CSR.
     * Strings are automatically converted to DNS names.
     *
     * @param altNames Alternative names for the subject (strings or GeneralName objects)
     * @returns This builder for chaining
     * @example
     * ```typescript
     * // Simple DNS names as strings
     * builder.addSubjectAltName('example.com', '*.example.com')
     *
     * // Or use GeneralName objects for other types
     * builder.addSubjectAltName(
     *     new GeneralName.dNSName({ value: 'example.com' }),
     *     new GeneralName.rfc822Name({ value: 'admin@example.com' })
     * )
     * ```
     */
    addSubjectAltName(...altNames: (string | GeneralName)[]): this {
        const generalNames = altNames.map((name) =>
            typeof name === 'string'
                ? new GeneralName.dNSName({ value: name })
                : name,
        )
        this.extensions.push(Extension.subjectAltName(generalNames))
        return this
    }

    /**
     * Adds an Extended Key Usage extension to the CSR.
     *
     * @param options Extended key usage purposes
     * @returns This builder for chaining
     * @example
     * ```typescript
     * builder.addExtendedKeyUsage({
     *     serverAuth: true,
     *     clientAuth: true
     * })
     * ```
     */
    addExtendedKeyUsage(
        options: {
            [key in ExtKeyCommonNames]?: boolean
        } & {
            [oid: string]: boolean
        },
    ): this {
        this.extensions.push(Extension.extendedKeyUsage(options))
        return this
    }

    /**
     * Sets the signature algorithm.
     *
     * @param algorithm Algorithm parameters or SignatureAlgorithmIdentifier
     * @returns This builder for chaining
     * @example
     * ```typescript
     * // Using algorithm parameters
     * builder.setAlgorithm({
     *     type: 'ECDSA',
     *     params: { namedCurve: 'P-256', hash: 'SHA-256' }
     * })
     * ```
     */
    setAlgorithm(
        algorithm:
            | AsymmetricEncryptionAlgorithmParams
            | SignatureAlgorithmIdentifier,
    ): this {
        this.algorithm = algorithm
        return this
    }

    /**
     * Validates that all required fields are set.
     * @throws Error if required fields are missing
     */
    private validate(): void {
        if (!this.subject) {
            throw new Error('Subject is required')
        }
        if (!this.publicKey) {
            throw new Error('Public key is required')
        }
        if (!this.privateKey) {
            throw new Error('Private key is required for signing CSR')
        }
    }

    /**
     * Builds and signs the certificate signing request.
     *
     * @returns Promise resolving to the signed CSR
     * @throws Error if required fields are missing
     */
    async build(): Promise<CertificateRequest> {
        this.validate()

        const signatureAlgorithm =
            this.algorithm instanceof SignatureAlgorithmIdentifier
                ? this.algorithm
                : AlgorithmIdentifier.signatureAlgorithm(
                      this.algorithm ?? {
                          type: 'RSASSA_PKCS1_v1_5',
                          params: { hash: 'SHA-256' },
                      },
                  )

        // Create attributes with extension request if extensions exist
        const attributes: Attribute[] = []
        if (this.extensions.length > 0) {
            const extensionsAsn1 = new asn1js.Sequence({
                value: this.extensions.map((ext) => ext.toAsn1()),
            })

            attributes.push(
                new Attribute({
                    type: OIDs.PKCS9.EXTENSION_REQUEST,
                    values: [new Uint8Array(extensionsAsn1.toBER())],
                }),
            )
        }

        const requestInfo = new CertificateRequestInfo({
            version: this.version,
            subject: this.subject!,
            publicKey: this.publicKey!,
            attributes: attributes.length > 0 ? attributes : undefined,
        })

        const signature = await signatureAlgorithm.sign(
            requestInfo.toDer(),
            this.privateKey!,
        )

        return new CertificateRequest({
            requestInfo,
            signatureAlgorithm,
            signature,
        })
    }
}
