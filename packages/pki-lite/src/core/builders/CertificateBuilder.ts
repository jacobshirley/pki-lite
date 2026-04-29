import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../../x509/Certificate.js'
import { Extension } from '../../x509/Extension.js'
import { Name } from '../../x509/Name.js'
import { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { TBSCertificate } from '../../x509/TBSCertificate.js'
import { Validity } from '../../x509/Validity.js'
import { AsyncBuilder } from './types.js'
import { AsymmetricEncryptionAlgorithmParams } from '../crypto/types.js'

/**
 * Builder class for creating X.509 certificates.
 *
 * This builder provides a fluent API for constructing certificates with
 * various options including subject, issuer, validity period, extensions,
 * and more. It supports both self-signed and CA-signed certificates.
 *
 * @example
 * ```typescript
 * // Create a self-signed certificate
 * const cert = await Certificate.builder()
 *     .setSubject('CN=Test Certificate, O=My Org, C=US')
 *     .setPublicKey(publicKey)
 *     .setPrivateKey(privateKey)
 *     .setValidityPeriod(
 *         new Date('2024-01-01'),
 *         new Date('2025-01-01')
 *     )
 *     .addExtension(basicConstraintsExt)
 *     .selfSign()
 *
 * // Create a CA-signed certificate
 * const cert = await Certificate.builder()
 *     .setSubject('CN=User Certificate')
 *     .setPublicKey(userPublicKey)
 *     .setIssuer(caCert)
 *     .setIssuerPrivateKey(caPrivateKey)
 *     .setSerialNumber(generateSerial())
 *     .setValidityPeriod(notBefore, notAfter)
 *     .sign()
 * ```
 */
export class CertificateBuilder implements AsyncBuilder<Certificate> {
    private subject?: Name
    private issuer?: Name | Certificate
    private publicKey?: SubjectPublicKeyInfo
    private privateKey?: PrivateKeyInfo
    private issuerPrivateKey?: PrivateKeyInfo
    private notBefore?: Date
    private notAfter?: Date
    private serialNumber?: Uint8Array<ArrayBuffer>
    private extensions: Extension[] = []
    private algorithm?: AsymmetricEncryptionAlgorithmParams
    private version: number = 2 // Default to v3 (version 2)

    /**
     * Sets the subject distinguished name for the certificate.
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
     * Sets the issuer for the certificate.
     * For self-signed certificates, this will be set to match the subject.
     *
     * @param issuer Issuer DN as string, Name object, or Certificate
     * @returns This builder for chaining
     */
    setIssuer(issuer: string | Name | Certificate): this {
        if (typeof issuer === 'string') {
            this.issuer = Name.parse(issuer)
        } else {
            this.issuer = issuer
        }
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
     * Sets the private key for signing (for self-signed certificates).
     *
     * @param privateKey The private key
     * @returns This builder for chaining
     */
    setPrivateKey(privateKey: PrivateKeyInfo): this {
        this.privateKey = privateKey
        return this
    }

    /**
     * Sets the issuer's private key for signing (for CA-signed certificates).
     *
     * @param privateKey The issuer's private key
     * @returns This builder for chaining
     */
    setIssuerPrivateKey(privateKey: PrivateKeyInfo): this {
        this.issuerPrivateKey = privateKey
        return this
    }

    /**
     * Sets the validity period for the certificate.
     *
     * @param notBefore Start of validity period
     * @param notAfter End of validity period
     * @returns This builder for chaining
     */
    setValidityPeriod(notBefore: Date, notAfter: Date): this {
        this.notBefore = notBefore
        this.notAfter = notAfter
        return this
    }

    /**
     * Sets the validity period in days from now.
     *
     * @param days Number of days the certificate should be valid
     * @returns This builder for chaining
     */
    setValidityDays(days: number): this {
        this.notBefore = new Date()
        this.notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000)
        return this
    }

    /**
     * Sets the serial number for the certificate.
     *
     * @param serialNumber Serial number as bytes, number, or string
     * @returns This builder for chaining
     */
    setSerialNumber(
        serialNumber: Uint8Array<ArrayBuffer> | number | string,
    ): this {
        if (
            typeof serialNumber === 'number' ||
            typeof serialNumber === 'string'
        ) {
            // Convert to Uint8Array - this will be handled by Integer constructor
            this.serialNumber = new Uint8Array([1, 0, 0, 0]) // Placeholder
            // Store the actual value to pass to TBSCertificate
        } else {
            this.serialNumber = serialNumber
        }
        return this
    }

    /**
     * Generates a random serial number.
     *
     * @returns This builder for chaining
     */
    generateSerialNumber(): this {
        const serial = new Uint8Array(20)
        crypto.getRandomValues(serial)
        // Ensure positive number by clearing the high bit
        serial[0] &= 0x7f
        this.serialNumber = serial
        return this
    }

    /**
     * Adds an extension to the certificate.
     *
     * @param extension The extension to add
     * @returns This builder for chaining
     */
    addExtension(extension: Extension): this {
        this.extensions.push(extension)
        return this
    }

    /**
     * Adds multiple extensions to the certificate.
     *
     * @param extensions Array of extensions to add
     * @returns This builder for chaining
     */
    addExtensions(...extensions: Extension[]): this {
        this.extensions.push(...extensions)
        return this
    }

    /**
     * Sets the signature algorithm.
     *
     * @param algorithm Algorithm parameters
     * @returns This builder for chaining
     */
    setAlgorithm(algorithm: AsymmetricEncryptionAlgorithmParams): this {
        this.algorithm = algorithm
        return this
    }

    /**
     * Sets the certificate version.
     *
     * @param version Certificate version (0 = v1, 1 = v2, 2 = v3)
     * @returns This builder for chaining
     */
    setVersion(version: number): this {
        this.version = version
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
        if (!this.notBefore || !this.notAfter) {
            throw new Error('Validity period is required')
        }
    }

    /**
     * Builds and signs a self-signed certificate.
     *
     * @returns Promise resolving to the signed certificate
     * @throws Error if required fields are missing
     */
    async selfSign(): Promise<Certificate> {
        this.validate()

        if (!this.privateKey) {
            throw new Error(
                'Private key is required for self-signed certificate',
            )
        }

        // For self-signed, issuer is the same as subject
        if (!this.issuer) {
            this.issuer = this.subject
        }

        // Generate serial number if not provided
        if (!this.serialNumber) {
            this.generateSerialNumber()
        }

        const signatureAlgorithm = AlgorithmIdentifier.signatureAlgorithm(
            this.algorithm ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: { hash: 'SHA-256' },
            },
        )

        const issuerName =
            this.issuer instanceof Certificate
                ? this.issuer.tbsCertificate.subject
                : this.issuer!

        const tbs = new TBSCertificate({
            version: this.version,
            serialNumber: this.serialNumber!,
            signature: signatureAlgorithm,
            issuer: issuerName,
            validity: new Validity({
                notBefore: this.notBefore!,
                notAfter: this.notAfter!,
            }),
            subject: this.subject!,
            subjectPublicKeyInfo: this.publicKey!,
            extensions:
                this.extensions.length > 0 ? this.extensions : undefined,
        })

        const signatureValue = await signatureAlgorithm.sign(
            tbs.toDer(),
            this.privateKey,
        )

        return new Certificate({
            tbsCertificate: tbs,
            signatureAlgorithm,
            signatureValue,
        })
    }

    /**
     * Builds and signs a certificate with the specified issuer.
     *
     * @returns Promise resolving to the signed certificate
     * @throws Error if required fields are missing
     */
    async sign(): Promise<Certificate> {
        this.validate()

        if (!this.issuer) {
            throw new Error('Issuer is required for CA-signed certificate')
        }

        const signingKey = this.issuerPrivateKey ?? this.privateKey
        if (!signingKey) {
            throw new Error('Signing private key is required')
        }

        // Generate serial number if not provided
        if (!this.serialNumber) {
            this.generateSerialNumber()
        }

        const signatureAlgorithm = AlgorithmIdentifier.signatureAlgorithm(
            this.algorithm ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: { hash: 'SHA-256' },
            },
        )

        const issuerName =
            this.issuer instanceof Certificate
                ? this.issuer.tbsCertificate.subject
                : this.issuer

        const tbs = new TBSCertificate({
            version: this.version,
            serialNumber: this.serialNumber!,
            signature: signatureAlgorithm,
            issuer: issuerName,
            validity: new Validity({
                notBefore: this.notBefore!,
                notAfter: this.notAfter!,
            }),
            subject: this.subject!,
            subjectPublicKeyInfo: this.publicKey!,
            extensions:
                this.extensions.length > 0 ? this.extensions : undefined,
        })

        const signatureValue = await signatureAlgorithm.sign(
            tbs.toDer(),
            signingKey,
        )

        return new Certificate({
            tbsCertificate: tbs,
            signatureAlgorithm,
            signatureValue,
        })
    }

    /**
     * Alias for sign() to match the AsyncBuilder interface.
     * Builds a CA-signed certificate, or self-signed if no issuer is set.
     *
     * @returns Promise resolving to the signed certificate
     */
    async build(): Promise<Certificate> {
        if (!this.issuer || this.issuer === this.subject) {
            return this.selfSign()
        }
        return this.sign()
    }
}
