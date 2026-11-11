import { Asn1BaseBlock, asn1js, derToAsn1, PkiBase } from '../core/PkiBase.js'
import { ContentInfo } from './ContentInfo.js'
import { OIDs } from '../core/OIDs.js'
import { OriginatorInfo } from './recipients/OriginatorInfo.js'
import { RecipientInfo } from './recipients/RecipientInfo.js'
import { KeyTransRecipientInfo } from './recipients/KeyTransRecipientInfo.js'
import { EnvelopedData } from './EnvelopedData.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { Attribute } from '../x509/Attribute.js'
import { Attributes } from '../x509/Attributes.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { CMSVersion } from './CMSVersion.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { implicitTag, isContextTag } from '../core/tagging.js'
import { getCryptoProvider } from '../core/crypto/provider.js'

/**
 * Represents a CMS AuthEnvelopedData structure (RFC 5083), what
 * `openssl cms -encrypt -aes-256-gcm` writes: EnvelopedData whose content is encrypted
 * with an authenticated cipher (AES-GCM or AES-CCM). The authentication tag is the
 * `mac` field and is not part of the encrypted content.
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
 */
export class AuthEnvelopedData extends PkiBase<AuthEnvelopedData> {
    /** Always 0 (RFC 5083 2.1) */
    version: CMSVersion
    originatorInfo?: OriginatorInfo
    recipientInfos: InstanceType<typeof EnvelopedData.RecipientInfos>
    /** The content, encrypted without its authentication tag */
    authEncryptedContentInfo: EncryptedContentInfo
    /** Authenticated attributes: covered by the tag as additional authenticated data */
    authAttrs?: Attributes
    /** The authentication tag */
    mac: Uint8Array<ArrayBuffer>
    unauthAttrs?: Attributes

    constructor(options: {
        version?: CMSVersion
        recipientInfos: RecipientInfo[]
        authEncryptedContentInfo: EncryptedContentInfo
        mac: Uint8Array<ArrayBuffer>
        originatorInfo?: OriginatorInfo
        authAttrs?: Attribute[]
        unauthAttrs?: Attribute[]
    }) {
        super()
        this.version = options.version ?? 0
        this.originatorInfo = options.originatorInfo
        this.recipientInfos = new EnvelopedData.RecipientInfos(
            ...options.recipientInfos,
        )
        this.authEncryptedContentInfo = options.authEncryptedContentInfo
        this.authAttrs = options.authAttrs?.length
            ? new Attributes(...options.authAttrs)
            : undefined
        this.mac = options.mac
        this.unauthAttrs = options.unauthAttrs?.length
            ? new Attributes(...options.unauthAttrs)
            : undefined
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
        ]
        if (this.originatorInfo) {
            values.push(implicitTag(this.originatorInfo.toAsn1(), 0))
        }
        values.push(this.recipientInfos.toAsn1())
        values.push(this.authEncryptedContentInfo.toAsn1())
        if (this.authAttrs) {
            values.push(implicitTag(this.authAttrs.toAsn1(), 1))
        }
        values.push(new asn1js.OctetString({ valueHex: this.mac }))
        if (this.unauthAttrs) {
            values.push(implicitTag(this.unauthAttrs.toAsn1(), 2))
        }
        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): AuthEnvelopedData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for AuthEnvelopedData',
            )
        }
        const values = asn1.valueBlock.value
        let index = 0

        const version = values[index]
        if (!(version instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        index++

        let originatorInfo: OriginatorInfo | undefined
        if (values[index] && isContextTag(values[index], 0)) {
            // originatorInfo [0] IMPLICIT OriginatorInfo (a SEQUENCE)
            originatorInfo = OriginatorInfo.fromAsn1(
                new asn1js.Sequence({
                    value: (values[index] as asn1js.Constructed).valueBlock
                        .value,
                }),
            )
            index++
        }

        if (!values[index]) {
            throw new Asn1ParseError(
                'AuthEnvelopedData: missing recipientInfos',
            )
        }
        const recipientInfos = EnvelopedData.RecipientInfos.fromAsn1(
            values[index++],
        )

        if (!values[index]) {
            throw new Asn1ParseError(
                'AuthEnvelopedData: missing authEncryptedContentInfo',
            )
        }
        const authEncryptedContentInfo = EncryptedContentInfo.fromAsn1(
            values[index++],
        )

        let authAttrs: Attributes | undefined
        if (values[index] && isContextTag(values[index], 1)) {
            authAttrs = Attributes.fromAsn1(values[index++])
        }

        const macBlock = values[index++]
        if (!(macBlock instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'AuthEnvelopedData: expected an OCTET STRING for mac',
            )
        }
        const mac = new Uint8Array(macBlock.valueBlock.valueHexView)

        let unauthAttrs: Attributes | undefined
        if (values[index] && isContextTag(values[index], 2)) {
            unauthAttrs = Attributes.fromAsn1(values[index++])
        }

        if (index < values.length) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: unexpected element after AuthEnvelopedData fields',
            )
        }

        return new AuthEnvelopedData({
            version: version.valueBlock.valueDec,
            originatorInfo,
            recipientInfos: [...recipientInfos],
            authEncryptedContentInfo,
            authAttrs: authAttrs ? [...authAttrs] : undefined,
            mac,
            unauthAttrs: unauthAttrs ? [...unauthAttrs] : undefined,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): AuthEnvelopedData {
        return AuthEnvelopedData.fromAsn1(derToAsn1(der))
    }

    static fromCms(
        cms: ContentInfo | Uint8Array<ArrayBuffer>,
    ): AuthEnvelopedData {
        if (cms instanceof Uint8Array) {
            cms = ContentInfo.fromDer(cms)
        }
        if (cms.contentType.toString() !== OIDs.PKCS7.AUTH_ENVELOPED_DATA) {
            throw new Asn1ParseError(
                `Invalid content type: expected ${OIDs.PKCS7.AUTH_ENVELOPED_DATA}, got ${cms.contentType}`,
            )
        }
        if (!cms.content) {
            throw new Error('ContentInfo has no content')
        }
        return cms.content.parseAs(AuthEnvelopedData)
    }

    toCms(): ContentInfo {
        return new ContentInfo({
            contentType: OIDs.PKCS7.AUTH_ENVELOPED_DATA,
            content: this,
        })
    }

    /**
     * Decrypts and authenticates the content with the key of a key-transport recipient.
     * Fails if the authentication tag does not match.
     */
    async decrypt(
        privateKey: PrivateKeyInfo,
    ): Promise<Uint8Array<ArrayBuffer>> {
        const ciphertext = this.authEncryptedContentInfo.encryptedContent
        if (!ciphertext) {
            throw new Error('Failed to retrieve encrypted content')
        }

        let contentKey: Uint8Array<ArrayBuffer> | undefined
        let lastError: unknown
        for (const recipientInfo of this.recipientInfos) {
            if (!(recipientInfo instanceof KeyTransRecipientInfo)) continue
            try {
                contentKey = await recipientInfo.keyEncryptionAlgorithm.decrypt(
                    recipientInfo.encryptedKey,
                    privateKey,
                )
                break
            } catch (e) {
                // Expected when the recipient belongs to a different key
                lastError = e
            }
        }
        if (!contentKey) {
            throw new Error('Failed to decrypt key', { cause: lastError })
        }

        const algorithm =
            this.authEncryptedContentInfo.contentEncryptionAlgorithm.toSymmetricEncryptionAlgorithmParams()
        if (
            algorithm.type !== 'AES_128_GCM' &&
            algorithm.type !== 'AES_192_GCM' &&
            algorithm.type !== 'AES_256_GCM'
        ) {
            throw new Error(
                `Unsupported authenticated content encryption: ${algorithm.type} (only AES-GCM is supported)`,
            )
        }

        // RFC 5083 2.2: the authenticated attributes, as a DER SET, are the AAD
        const additionalData = this.authAttrs
            ? this.authAttrs.toDer()
            : undefined

        // WebCrypto expects the tag appended to the ciphertext
        const sealed = new Uint8Array(ciphertext.bytes.length + this.mac.length)
        sealed.set(ciphertext.bytes, 0)
        sealed.set(this.mac, ciphertext.bytes.length)

        return await getCryptoProvider().decryptSymmetric(sealed, contentKey, {
            type: algorithm.type,
            params: {
                ...algorithm.params,
                icvLen: this.mac.length * 8,
                ...(additionalData ? { additionalData } : {}),
            },
        } as typeof algorithm)
    }
}
