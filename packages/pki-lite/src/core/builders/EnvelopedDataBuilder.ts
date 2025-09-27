/**
 * Builder for constructing CMS EnvelopedData structures.
 *
 * EnvelopedData provides confidentiality by encrypting data for one or more recipients.
 * Each recipient's public key is used to encrypt a randomly generated symmetric key,
 * which in turn encrypts the actual data content. This allows multiple recipients
 * to decrypt the same encrypted data using their respective private keys.
 *
 * @asn EnvelopedData ::= SEQUENCE {
 *   version CMSVersion,
 *   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *   recipientInfos RecipientInfos,
 *   encryptedContentInfo EncryptedContentInfo,
 *   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 *
 * @example
 * ```typescript
 * // Create enveloped data for multiple recipients
 * const envelopedData = await new EnvelopedDataBuilder()
 *     .setData("Confidential message")
 *     .setContentEncryptionAlgorithm({ type: 'AES_256_GCM', params: { nonce: randomBytes(12) } })
 *     .addRecipient({ certificate: recipientCert1 })
 *     .addRecipient({
 *         certificate: recipientCert2,
 *         keyEncryptionAlgorithm: { type: 'RSA_OAEP', params: { hash: 'SHA-256' } }
 *     })
 *     .addCrl(latestCrl)
 *     .build()
 *
 * // Each recipient can decrypt using their private key
 * const decryptedData = await envelopedData.decrypt(recipient1PrivateKey)
 * ```
 *
 * @see RFC 5652 Section 6 - Enveloped-data Content Type
 */

import {
    AlgorithmIdentifier,
    KeyEncryptionAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../../x509/Certificate.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    SymmetricEncryptionAlgorithmParams,
} from '../crypto/types.js'
import { EncryptedContentInfo } from '../../pkcs7/EncryptedContentInfo.js'
import { EnvelopedData } from '../../pkcs7/EnvelopedData.js'
import { IssuerAndSerialNumber } from '../../pkcs7/IssuerAndSerialNumber.js'
import { OIDs } from '../OIDs.js'
import { RecipientInfo } from '../../pkcs7/recipients/RecipientInfo.js'
import { KeyTransRecipientInfo } from '../../pkcs7/recipients/KeyTransRecipientInfo.js'
import { AsyncBuilder } from './types.js'
import { RSAESOAEPParams } from '../../algorithms/RSAESOAEPParams.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { ObjectIdentifierString } from '../PkiBase.js'
import { OriginatorInfo } from '../../pkcs7/recipients/OriginatorInfo.js'
import { RevocationInfoChoice } from '../../revocation/RevocationInfoChoice.js'
import { OtherRevocationInfoFormat } from '../../revocation/OtherRevocationInfoFormat.js'
import { OCSPResponse } from '../../ocsp/OCSPResponse.js'
import { CertificateList } from '../../x509/CertificateList.js'
import { CertificateChoices } from '../../x509/CertificateChoices.js'
import { OtherRecipientInfo } from '../../pkcs7/recipients/OtherRecipientInfo.js'

/**
 * Configuration for a recipient of enveloped data.
 *
 * @example
 * ```typescript
 * const recipient: EnvelopedDataBuilderRecipient = {
 *     certificate: recipientCert,
 *     keyEncryptionAlgorithm: {
 *         type: 'RSA_OAEP',
 *         params: { hash: 'SHA-384' }
 *     }
 * }
 * ```
 */
export type EnvelopedDataBuilderRecipient = {
    /** The recipient's certificate containing their public key */
    certificate: Certificate
    /** Optional key encryption algorithm, defaults to RSA-OAEP with SHA-1 */
    keyEncryptionAlgorithm?: AsymmetricEncryptionAlgorithmParams
}

/**
 * Builder class for creating CMS EnvelopedData structures.
 *
 * This builder allows setting the data to be encrypted, the content encryption algorithm,
 * and adding multiple recipients who can decrypt the data. It also supports including
 * certificates and revocation information in the originator info.
 *
 * @example
 * ```typescript
 *
 * const recipientCert1 = Certificate.fromPem(`-----BEGIN CERTIFICATE-----')
 * const recipientCert2 = Certificate.fromPem(`-----BEGIN CERTIFICATE-----')
 *
 * const builder = new EnvelopedDataBuilder()
 * builder.setData("Secret message")
 * builder.setContentEncryptionAlgorithm({ type: 'AES_256_GCM', params: { nonce: randomBytes(12) } })
 * builder.addRecipient({ certificate: recipientCert1 })
 * builder.addRecipient({
 *     certificate: recipientCert2,
 *     keyEncryptionAlgorithm: {
 *         type: 'RSA_OAEP',
 *         params: { hash: 'SHA-384' }
 *     }
 * })
 * const envelopedData = await builder.build()
 * const der = envelopedData.toDer()
 */
export class EnvelopedDataBuilder implements AsyncBuilder<EnvelopedData> {
    /**
     * Default key encryption algorithm (RSA-OAEP with SHA-1).
     * Used when no specific key encryption algorithm is provided for a recipient.
     */
    static readonly DEFAULT_KEY_ENCRYPTION_ALGORITHM =
        new KeyEncryptionAlgorithmIdentifier({
            algorithm: OIDs.RSA.RSAES_OAEP,
            parameters: RSAESOAEPParams.createDefault(),
        })

    /** The data to be encrypted */
    data?: Uint8Array

    /** Content type identifier, defaults to PKCS#7 data */
    contentType: ObjectIdentifier = new ObjectIdentifier({
        value: OIDs.PKCS7.DATA,
    })

    /** Recipients who can decrypt the enveloped data */
    recipients: EnvelopedDataBuilderRecipient[] = []

    /** Algorithm used to encrypt the content */
    contentEncryptionAlgorithm?: SymmetricEncryptionAlgorithmParams

    /** Optional certificates to include in originator info */
    certificates?: CertificateChoices[]

    /** Certificate Revocation Lists to include */
    crls: RevocationInfoChoice[] = []

    /**
     * Sets the data to be encrypted and optionally the content type.
     *
     * @param data The data to encrypt, either as bytes or string
     * @param contentType Optional content type identifier
     * @returns This builder instance for method chaining
     *
     * @example
     * ```typescript
     * builder.setData("Secret message")
     * builder.setData(documentBytes, "1.2.840.113549.1.7.1") // PKCS#7 data
     * ```
     */
    setData(
        data: Uint8Array | string,
        contentType?: ObjectIdentifierString,
    ): this {
        this.data =
            typeof data === 'string' ? new TextEncoder().encode(data) : data

        if (contentType) {
            this.contentType = new ObjectIdentifier({ value: contentType })
        }

        return this
    }

    /**
     * Sets the content type identifier for the encrypted data.
     *
     * @param type The content type as ObjectIdentifier or string
     * @returns This builder instance for method chaining
     *
     * @example
     * ```typescript
     * builder.setContentType("1.2.840.113549.1.7.1") // PKCS#7 data
     * builder.setContentType(new ObjectIdentifier({ value: "1.2.840.113549.1.9.16.1.4" })) // eContentTypes id-alg-pwri-kek
     * ```
     */
    setContentType(type: ObjectIdentifier | ObjectIdentifierString): this {
        this.contentType = new ObjectIdentifier({
            value: type,
        })
        return this
    }

    /**
     * Sets the symmetric encryption algorithm used to encrypt the content.
     * If not set, defaults to AES-256-CBC with a random IV.
     *
     * @param algorithm The content encryption algorithm parameters
     * @returns This builder instance for method chaining
     *
     * @example
     * ```typescript
     * builder.setContentEncryptionAlgorithm({
     *     type: 'AES_256_GCM',
     *     params: { nonce: crypto.getRandomValues(new Uint8Array(12)) }
     * })
     * ```
     */
    setContentEncryptionAlgorithm(
        algorithm: SymmetricEncryptionAlgorithmParams,
    ): this {
        this.contentEncryptionAlgorithm = algorithm
        return this
    }

    /**
     * Adds one or more recipients who can decrypt the enveloped data.
     * Each recipient's public key will be used to encrypt the content encryption key.
     *
     * @param recipient One or more recipient configurations
     * @returns This builder instance for method chaining
     *
     * @example
     * ```typescript
     * builder.addRecipient(
     *     { certificate: cert1 },
     *     {
     *         certificate: cert2,
     *         keyEncryptionAlgorithm: { type: 'RSA_OAEP', params: { hash: 'SHA-384' } }
     *     }
     * )
     * ```
     */
    addRecipient(...recipient: EnvelopedDataBuilderRecipient[]): this {
        this.recipients.push(...recipient)
        return this
    }

    /**
     * Adds a Certificate Revocation List to the enveloped data.
     * CRLs can be used by recipients to verify certificate validity.
     *
     * @param crl The certificate revocation list to include
     * @returns This builder instance for method chaining
     *
     * @example
     * ```typescript
     * builder.addCrl(latestCrl)
     * ```
     */
    addCrl(crl: CertificateList): this {
        this.crls.push(crl)
        return this
    }

    /**
     * Adds an OCSP response to the enveloped data for certificate status validation.
     * OCSP responses provide real-time certificate revocation status.
     *
     * @param ocsp The OCSP response to include
     * @returns This builder instance for method chaining
     *
     * @example
     * ```typescript
     * builder.addOcsp(ocspResponse)
     * ```
     */
    addOcsp(ocsp: OCSPResponse): this {
        this.crls.push(
            new OtherRevocationInfoFormat({
                otherRevInfoFormat: OIDs.OTHER_REV_INFO.OCSP,
                otherRevInfo: ocsp,
            }),
        )
        return this
    }

    /**
     * Gets the originator info containing certificates and CRLs.
     * Returns undefined if no certificates are present.
     *
     * @returns OriginatorInfo or undefined
     */
    get originatorInfo(): OriginatorInfo | undefined {
        if (!this.certificates || this.certificates.length === 0) {
            return undefined
        }

        return new OriginatorInfo({
            certs: this.certificates,
            crls: this.crls,
        })
    }

    /**
     * Determines the CMS version based on the presence of originator info and recipient types.
     *
     * Version rules (per RFC 5652):
     * - Version 2: if originatorInfo is present, any RecipientInfo has version != 0, or unprotectedAttrs present
     * - Version 0: if originatorInfo is absent, all RecipientInfo structures are version 0, and unprotectedAttrs absent
     *
     * @param recipients The recipient info structures
     * @returns The appropriate CMS version number
     */
    private getVersion(recipients: RecipientInfo[]): number {
        if (this.originatorInfo) {
            return 2
        }

        if (
            recipients.some(
                (r) => r instanceof OtherRecipientInfo || r.version !== 0,
            )
        ) {
            return 2
        }

        return 0
    }

    /**
     * Builds the EnvelopedData structure by encrypting the content and creating recipient infos.
     *
     * The build process:
     * 1. Generates a random symmetric key for content encryption
     * 2. Encrypts the data with the symmetric key
     * 3. For each recipient, encrypts the symmetric key with their public key
     * 4. Creates the final EnvelopedData structure
     *
     * @returns Promise resolving to the constructed EnvelopedData
     * @throws Error if no data is set or no recipients are specified
     *
     * @example
     * ```typescript
     * const envelopedData = await builder
     *     .setData("Confidential document")
     *     .addRecipient({ certificate: recipientCert })
     *     .build()
     *
     * // The enveloped data can now be transmitted securely
     * const der = envelopedData.toASN1().toDER()
     * ```
     */
    async build(): Promise<EnvelopedData> {
        const data = this.data
        if (!data) {
            throw new Error('No data to encrypt')
        }

        if (this.recipients.length === 0) {
            throw new Error('At least one recipient must be specified')
        }

        if (!this.contentEncryptionAlgorithm) {
            this.contentEncryptionAlgorithm = {
                type: 'AES_256_CBC',
                params: {
                    nonce: AlgorithmIdentifier.randomBytes(16),
                },
            }
        }

        const contentEncryptionAlgorithm =
            AlgorithmIdentifier.contentEncryptionAlgorithm(
                this.contentEncryptionAlgorithm,
            )

        const contentEncryptionKey = contentEncryptionAlgorithm.generateKey()

        const encryptedContent = await contentEncryptionAlgorithm.encrypt(
            data,
            contentEncryptionKey,
        )

        const encryptedContentInfo = new EncryptedContentInfo({
            contentType: this.contentType,
            contentEncryptionAlgorithm,
            encryptedContent: encryptedContent,
        })

        const recipientInfos: RecipientInfo[] = await Promise.all(
            this.recipients.map(async (recipient) => {
                const keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier =
                    recipient.keyEncryptionAlgorithm
                        ? AlgorithmIdentifier.keyEncryptionAlgorithm(
                              recipient.keyEncryptionAlgorithm,
                          )
                        : EnvelopedDataBuilder.DEFAULT_KEY_ENCRYPTION_ALGORITHM

                const issuerAndSerialNumber = new IssuerAndSerialNumber({
                    issuer: recipient.certificate.tbsCertificate.issuer,
                    serialNumber:
                        recipient.certificate.tbsCertificate.serialNumber,
                })

                const publicKey =
                    recipient.certificate.tbsCertificate.subjectPublicKeyInfo

                const encryptedKey = await keyEncryptionAlgorithm.encrypt(
                    contentEncryptionKey,
                    publicKey,
                )

                const ktri = new KeyTransRecipientInfo({
                    rid: issuerAndSerialNumber,
                    keyEncryptionAlgorithm,
                    encryptedKey,
                })

                return ktri
            }),
        )

        return new EnvelopedData({
            version: this.getVersion(recipientInfos),
            recipientInfos,
            encryptedContentInfo,
        })
    }
}
