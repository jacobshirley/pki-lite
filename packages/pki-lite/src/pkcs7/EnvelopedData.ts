import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    PkiBase,
    PkiSet,
} from '../core/PkiBase.js'
import { RecipientInfo } from './recipients/RecipientInfo.js'
import { EnvelopedDataBuilder } from '../core/builders/EnvelopedDataBuilder.js'
import { ContentInfo } from './ContentInfo.js'
import { OIDs } from '../core/OIDs.js'
import {
    OriginatorInfo,
    RevocationInfoChoices,
} from './recipients/OriginatorInfo.js'
import { Attribute } from '../x509/Attribute.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { KeyTransRecipientInfo } from './recipients/KeyTransRecipientInfo.js'
import { CMSVersion } from './CMSVersion.js'
import { Attributes } from '../x509/Attributes.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from '../revocation/OtherRevocationInfoFormat.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of unprotected attributes.
 *
 * @asn
 * ```
 * UnprotectedAttributes ::= SET SIZE (0..MAX) OF Attribute
 * ```
 */
const UnprotectedAttributes = Attributes
type UnprotectedAttributes = Attributes

/**
 * Represents a set of RecipientInfo structures.
 *
 * @asn
 * ```
 * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 * ```
 */
class RecipientInfos extends PkiSet<RecipientInfo> {
    static fromAsn1(asn1: Asn1BaseBlock): RecipientInfos {
        if (!(asn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for RecipientInfos',
            )
        }

        const recipients = asn1.valueBlock.value.map((recAsn1) =>
            RecipientInfo.fromAsn1(recAsn1),
        )

        return new RecipientInfos(...recipients)
    }
}

/**
 * Represents a CMS EnvelopedData structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * EnvelopedData ::= SEQUENCE {
 *     version CMSVersion,
 *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos RecipientInfos,
 *     encryptedContentInfo EncryptedContentInfo,
 *     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 * ```
 */
export class EnvelopedData extends PkiBase<EnvelopedData> {
    /**
     * Represents a set of RecipientInfo structures.
     *
     * @asn
     * ```
     * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
     * ```
     */
    static RecipientInfos = RecipientInfos
    static UnprotectedAttributes = UnprotectedAttributes

    /**
     * The version of the EnvelopedData structure.
     */
    version: CMSVersion

    /**
     * Optional information about the originator.
     */
    originatorInfo?: OriginatorInfo

    /**
     * A collection of per-recipient information.
     */
    recipientInfos: RecipientInfos

    /**
     * The encrypted content and associated parameters.
     */
    encryptedContentInfo: EncryptedContentInfo

    /**
     * Optional unprotected attributes.
     */
    unprotectedAttrs?: UnprotectedAttributes

    /**
     * Creates a new EnvelopedData instance.
     */
    constructor(options: {
        version: CMSVersion
        recipientInfos: RecipientInfo[]
        encryptedContentInfo: EncryptedContentInfo
        originatorInfo?: OriginatorInfo
        unprotectedAttrs?: Attribute[]
    }) {
        super()

        const {
            version,
            recipientInfos,
            encryptedContentInfo,
            originatorInfo,
            unprotectedAttrs,
        } = options

        this.version = version
        this.originatorInfo = originatorInfo
        this.recipientInfos = new RecipientInfos(...recipientInfos)
        this.encryptedContentInfo = encryptedContentInfo
        this.unprotectedAttrs =
            unprotectedAttrs && unprotectedAttrs.length > 0
                ? new UnprotectedAttributes(...unprotectedAttrs)
                : undefined
    }

    /**
     * Converts the EnvelopedData to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values = []

        // Version is always present
        values.push(new asn1js.Integer({ value: this.version }))

        // Add originatorInfo if present
        if (this.originatorInfo) {
            const asn1 = this.originatorInfo.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 0 // [0]
            values.push(asn1)
        }

        // RecipientInfos is always present
        values.push(this.recipientInfos.toAsn1())

        // EncryptedContentInfo is always present
        values.push(this.encryptedContentInfo.toAsn1())

        // Add unprotectedAttrs if present
        if (this.unprotectedAttrs && this.unprotectedAttrs.length > 0) {
            const asn1 = this.unprotectedAttrs.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 1 // [1]
            values.push(asn1)
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    /**
     * Creates an EnvelopedData from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): EnvelopedData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 3) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 3 elements, got ${values.length}`,
            )
        }

        let currentIndex = 0

        // Version - always first
        if (!(values[currentIndex] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }

        const version = (values[currentIndex] as asn1js.Integer).valueBlock
            .valueDec

        currentIndex++
        // OriginatorInfo - optional [0]
        let originatorInfo: OriginatorInfo | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 0 // [0]
        ) {
            const originatorInfoAsn1 = (
                values[currentIndex] as asn1js.Constructed
            ).valueBlock.value[0]
            originatorInfo = OriginatorInfo.fromAsn1(originatorInfoAsn1)
            currentIndex++
        }

        const recipientInfosSet = values[currentIndex]
        const recipientInfos = RecipientInfos.fromAsn1(recipientInfosSet)
        currentIndex++

        // EncryptedContentInfo - required
        if (currentIndex >= values.length) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: missing encryptedContentInfo',
            )
        }
        const encryptedContentInfo = EncryptedContentInfo.fromAsn1(
            values[currentIndex],
        )
        currentIndex++

        // UnprotectedAttrs - optional [1]
        let unprotectedAttrs: UnprotectedAttributes | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 1 // [1]
        ) {
            const unprotectedAttrsAsn1 = (
                values[currentIndex] as asn1js.Constructed
            ).valueBlock.value[0]
            unprotectedAttrs =
                UnprotectedAttributes.fromAsn1(unprotectedAttrsAsn1)
        }

        return new EnvelopedData({
            version,
            recipientInfos,
            encryptedContentInfo,
            originatorInfo,
            unprotectedAttrs,
        })
    }

    static fromDer(der: Uint8Array): EnvelopedData {
        return EnvelopedData.fromAsn1(derToAsn1(der))
    }

    static fromCms(cms: ContentInfo | Uint8Array): EnvelopedData {
        if (cms instanceof Uint8Array) {
            cms = ContentInfo.fromDer(cms)
        }

        if (cms.contentType.toString() !== OIDs.PKCS7.ENVELOPED_DATA) {
            throw new Asn1ParseError(
                `Invalid content type: expected ${OIDs.PKCS7.ENVELOPED_DATA}, got ${cms.contentType}`,
            )
        }

        if (!cms.content) {
            throw new Error('ContentInfo has no content')
        }

        return cms.content.parseAs(EnvelopedData)
    }

    static builder() {
        return new EnvelopedDataBuilder()
    }

    toCms(): ContentInfo {
        return new ContentInfo({
            contentType: OIDs.PKCS7.ENVELOPED_DATA,
            content: this,
        })
    }

    async decrypt(privateKey: PrivateKeyInfo): Promise<Uint8Array> {
        const encryptedContent = this.encryptedContentInfo.encryptedContent

        if (!encryptedContent) {
            throw new Error('Failed to retrieve encrypted content')
        }

        let decryptedKey: Uint8Array | undefined
        for (const recipientInfo of this.recipientInfos) {
            try {
                if (recipientInfo instanceof KeyTransRecipientInfo) {
                    const encryptedKey = recipientInfo.encryptedKey

                    decryptedKey =
                        await recipientInfo.keyEncryptionAlgorithm.decrypt(
                            encryptedKey,
                            privateKey,
                        )
                }
            } catch (e) {
                console.error('Error decrypting key:', e)
            }
        }

        if (!decryptedKey) {
            throw new Error('Failed to decrypt key')
        }

        const originalContent =
            await this.encryptedContentInfo.decrypt(decryptedKey)

        return originalContent.toUint8Array()
    }

    addOcsp(OCSP: OCSPResponse): void {
        this.originatorInfo = this.originatorInfo ?? new OriginatorInfo()
        this.originatorInfo.crls =
            this.originatorInfo.crls ?? new RevocationInfoChoices()
        this.originatorInfo.crls.push(
            new OtherRevocationInfoFormat({
                otherRevInfoFormat: OIDs.OTHER_REV_INFO.OCSP,
                otherRevInfo: OCSP,
            }),
        )
    }

    addCrl(crl: CertificateList): void {
        this.originatorInfo = this.originatorInfo ?? new OriginatorInfo()
        this.originatorInfo.crls =
            this.originatorInfo.crls ?? new RevocationInfoChoices()
        this.originatorInfo.crls.push(crl)
    }
}
