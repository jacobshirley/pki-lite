import {
    AlgorithmIdentifier,
    ContentEncryptionAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { Attribute } from '../../x509/Attribute.js'
import { Attributes } from '../../x509/Attributes.js'
import { AuthEnvelopedData } from '../../pkcs7/AuthEnvelopedData.js'
import { EncryptedContentInfo } from '../../pkcs7/EncryptedContentInfo.js'
import { OIDs } from '../OIDs.js'
import { ObjectIdentifierString } from '../PkiBase.js'
import { getCryptoProvider } from '../crypto/provider.js'
import { SymmetricEncryptionAlgorithmParams } from '../crypto/types.js'
import {
    EnvelopedDataBuilder,
    EnvelopedDataBuilderRecipient,
} from './EnvelopedDataBuilder.js'
import { AsyncBuilder } from './types.js'

/** The authenticated ciphers AuthEnvelopedData can be built with. */
export type AuthEnvelopedDataCipher = Extract<
    SymmetricEncryptionAlgorithmParams,
    { type: 'AES_128_GCM' | 'AES_192_GCM' | 'AES_256_GCM' }
>

/**
 * Builder for CMS AuthEnvelopedData structures (RFC 5083): like EnvelopedData, but the
 * content is encrypted with AES-GCM, so it is also authenticated. The authentication
 * tag is stored as `mac`, and any authenticated attributes are covered by it as
 * additional authenticated data.
 *
 * @asn
 * ```asn
 * AuthEnvelopedData ::= SEQUENCE {
 *      version CMSVersion,
 *      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *      recipientInfos RecipientInfos,
 *      authEncryptedContentInfo EncryptedContentInfo,
 *      authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
 *      mac MessageAuthenticationCode,
 *      unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL
 * }
 * ```
 *
 * @example
 * ```typescript
 * const authEnvelopedData = await AuthEnvelopedData.builder()
 *     .setData('Confidential message')
 *     .addRecipient({ certificate: recipientCert })
 *     .build()
 *
 * const plaintext = await authEnvelopedData.decrypt(recipientPrivateKey)
 * ```
 *
 * @see RFC 5083 - Cryptographic Message Syntax (CMS) Authenticated-Enveloped-Data Content Type
 */
export class AuthEnvelopedDataBuilder
    implements AsyncBuilder<AuthEnvelopedData>
{
    /** The data to be encrypted */
    data?: Uint8Array<ArrayBuffer>

    /** Content type identifier, defaults to PKCS#7 data */
    contentType: ObjectIdentifier = new ObjectIdentifier({
        value: OIDs.PKCS7.DATA,
    })

    /** Recipients who can decrypt the data */
    recipients: EnvelopedDataBuilderRecipient[] = []

    /** The AES-GCM cipher and its nonce / tag length; defaults to AES-256-GCM */
    contentEncryptionAlgorithm?: AuthEnvelopedDataCipher

    /** Authenticated attributes, covered by the authentication tag */
    authAttrs: Attribute[] = []

    /** Unauthenticated attributes */
    unauthAttrs: Attribute[] = []

    /**
     * Sets the data to be encrypted and optionally the content type.
     */
    setData(
        data: Uint8Array<ArrayBuffer> | string,
        contentType?: ObjectIdentifierString,
    ): this {
        this.data =
            typeof data === 'string' ? new TextEncoder().encode(data) : data
        if (contentType) {
            this.setContentType(contentType)
        }
        return this
    }

    setContentType(type: ObjectIdentifier | ObjectIdentifierString): this {
        this.contentType = new ObjectIdentifier({ value: type })
        return this
    }

    /**
     * Sets the AES-GCM cipher. `nonce` is the IV (12 bytes recommended) and `icvLen` the
     * authentication tag length in bytes (12 to 16, default 16).
     *
     * @example
     * ```typescript
     * builder.setContentEncryptionAlgorithm({
     *     type: 'AES_128_GCM',
     *     params: { nonce: crypto.getRandomValues(new Uint8Array(12)), icvLen: 16 },
     * })
     * ```
     */
    setContentEncryptionAlgorithm(algorithm: AuthEnvelopedDataCipher): this {
        this.contentEncryptionAlgorithm = algorithm
        return this
    }

    addRecipient(...recipient: EnvelopedDataBuilderRecipient[]): this {
        this.recipients.push(...recipient)
        return this
    }

    /** Adds attributes that are authenticated along with the content. */
    addAuthenticatedAttribute(...attributes: Attribute[]): this {
        this.authAttrs.push(...attributes)
        return this
    }

    addUnauthenticatedAttribute(...attributes: Attribute[]): this {
        this.unauthAttrs.push(...attributes)
        return this
    }

    /**
     * Encrypts the data and creates the recipient infos.
     *
     * @throws Error if no data or no recipient is set, or the cipher is not AES-GCM
     */
    async build(): Promise<AuthEnvelopedData> {
        const data = this.data
        if (!data) {
            throw new Error('No data to encrypt')
        }
        if (this.recipients.length === 0) {
            throw new Error('At least one recipient must be specified')
        }

        const cipher: AuthEnvelopedDataCipher = this
            .contentEncryptionAlgorithm ?? {
            type: 'AES_256_GCM',
            params: { nonce: AlgorithmIdentifier.randomBytes(12) },
        }
        if (
            cipher.type !== 'AES_128_GCM' &&
            cipher.type !== 'AES_192_GCM' &&
            cipher.type !== 'AES_256_GCM'
        ) {
            throw new Error(
                `AuthEnvelopedData needs an AES-GCM cipher, got ${String((cipher as { type: string }).type)}`,
            )
        }
        const icvLen = cipher.params.icvLen ?? 16
        if (icvLen < 12 || icvLen > 16) {
            throw new Error(
                `The authentication tag length must be 12 to 16 bytes, got ${icvLen}`,
            )
        }
        const params = { ...cipher.params, icvLen }

        // RFC 5083 2.1: authAttrs must carry the content-type attribute, and must be
        // present when the content type is not id-data.
        const authAttrs = [...this.authAttrs]
        const hasContentType = authAttrs.some(
            (attribute) => attribute.type.value === OIDs.PKCS9.CONTENT_TYPE,
        )
        if (
            !hasContentType &&
            (authAttrs.length > 0 || this.contentType.value !== OIDs.PKCS7.DATA)
        ) {
            authAttrs.push(
                new Attribute({
                    type: OIDs.PKCS9.CONTENT_TYPE,
                    values: [this.contentType],
                }),
            )
        }
        // DER requires the elements of a SET OF to be sorted by encoding
        const encoded = authAttrs.map((attribute) => ({
            attribute,
            der: attribute.toDer(),
        }))
        encoded.sort((a, b) => compareBytes(a.der, b.der))
        const sortedAuthAttrs = encoded.map((entry) => entry.attribute)
        const additionalData = sortedAuthAttrs.length
            ? new Attributes(...sortedAuthAttrs).toDer()
            : undefined

        const contentEncryptionAlgorithm: ContentEncryptionAlgorithmIdentifier =
            AlgorithmIdentifier.contentEncryptionAlgorithm({
                type: cipher.type,
                params: { nonce: params.nonce, icvLen },
            } as AuthEnvelopedDataCipher)
        const contentEncryptionKey = contentEncryptionAlgorithm.generateKey()

        // WebCrypto returns the ciphertext with the tag appended
        const sealed = await getCryptoProvider().encryptSymmetric(
            data,
            contentEncryptionKey,
            {
                type: cipher.type,
                params: {
                    nonce: params.nonce,
                    icvLen,
                    ...(additionalData ? { additionalData } : {}),
                },
            } as AuthEnvelopedDataCipher,
        )
        const ciphertext = sealed.slice(0, sealed.length - icvLen)
        const mac = sealed.slice(sealed.length - icvLen)

        const recipientInfos = await Promise.all(
            this.recipients.map((recipient) =>
                EnvelopedDataBuilder.createRecipientInfo(
                    recipient,
                    contentEncryptionKey,
                ),
            ),
        )

        return new AuthEnvelopedData({
            recipientInfos,
            authEncryptedContentInfo: new EncryptedContentInfo({
                contentType: this.contentType,
                contentEncryptionAlgorithm,
                encryptedContent: ciphertext,
            }),
            authAttrs: sortedAuthAttrs,
            mac,
            unauthAttrs: this.unauthAttrs,
        })
    }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const length = Math.min(a.length, b.length)
    for (let i = 0; i < length; i++) {
        if (a[i] !== b[i]) return a[i] - b[i]
    }
    return a.length - b.length
}
