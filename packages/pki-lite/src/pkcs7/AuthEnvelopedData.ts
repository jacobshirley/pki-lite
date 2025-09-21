import { Asn1BaseBlock, asn1js, PkiBase, PkiSet } from '../core/PkiBase.js'
import { RecipientInfo } from './recipients/RecipientInfo.js'
import { OriginatorInfo } from './recipients/OriginatorInfo.js'
import { Attribute } from '../x509/Attribute.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { CMSVersion } from './CMSVersion.js'
import { ContentInfo } from './ContentInfo.js'
import { OIDs } from '../core/OIDs.js'
import { Attributes } from '../x509/Attributes.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of authenticated attributes.
 *
 * @asn
 * ```asn
 * AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
const AuthAttributes = Attributes
type AuthAttributes = Attributes

/**
 * Represents a set of unauthenticated attributes.
 *
 * @asn
 * ```asn
 * UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
const UnauthAttributes = Attributes
type UnauthAttributes = Attributes

/**
 * Represents a set of RecipientInfo structures.
 *
 * @asn
 * ```asn
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
 * Message Authentication Code
 *
 * @asn
 * ```asn
 * MessageAuthenticationCode ::= OCTET STRING
 * ```
 */
class MessageAuthenticationCode extends Uint8Array {
    static fromAsn1(asn1: Asn1BaseBlock): MessageAuthenticationCode {
        if (!(asn1 instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for MessageAuthenticationCode',
            )
        }

        return new MessageAuthenticationCode(asn1.valueBlock.valueHexView)
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.OctetString({
            valueHex: this,
        })
    }
}

/**
 * Authenticated Enveloped Data
 *
 * @asn
 * ```asn
 * AuthEnvelopedData ::= SEQUENCE {
 *     version CMSVersion,
 *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos RecipientInfos,
 *     authEncryptedContentInfo EncryptedContentInfo,
 *     authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
 *     mac MessageAuthenticationCode,
 *     unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL
 * }
 * ```
 */
export class AuthEnvelopedData extends PkiBase<AuthEnvelopedData> {
    /**
     * Internal RecipientInfos class
     */
    static RecipientInfos = RecipientInfos

    /**
     * Internal AuthAttributes class
     */
    static AuthAttributes = AuthAttributes

    /**
     * Internal UnauthAttributes class
     */
    static UnauthAttributes = UnauthAttributes

    /**
     * Internal MessageAuthenticationCode class
     */
    static MessageAuthenticationCode = MessageAuthenticationCode

    /**
     * The version of the AuthEnvelopedData structure.
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
     * The authenticated encrypted content and associated parameters.
     */
    authEncryptedContentInfo: EncryptedContentInfo

    /**
     * Optional authenticated attributes.
     */
    authAttrs?: AuthAttributes

    /**
     * The message authentication code.
     */
    mac: MessageAuthenticationCode

    /**
     * Optional unauthenticated attributes.
     */
    unauthAttrs?: UnauthAttributes

    /**
     * Creates a new AuthEnvelopedData instance.
     */
    constructor(options: {
        version: CMSVersion
        recipientInfos: RecipientInfo[]
        authEncryptedContentInfo: EncryptedContentInfo
        mac: Uint8Array
        originatorInfo?: OriginatorInfo
        authAttrs?: Attribute[]
        unauthAttrs?: Attribute[]
    }) {
        super()

        const {
            version,
            recipientInfos,
            authEncryptedContentInfo,
            mac,
            originatorInfo,
            authAttrs,
            unauthAttrs,
        } = options

        this.version = version
        this.recipientInfos = new RecipientInfos(...recipientInfos)
        this.authEncryptedContentInfo = authEncryptedContentInfo
        this.mac = new MessageAuthenticationCode(mac)
        this.originatorInfo = originatorInfo
        this.authAttrs =
            authAttrs && authAttrs.length > 0
                ? new AuthAttributes(...authAttrs)
                : undefined
        this.unauthAttrs =
            unauthAttrs && unauthAttrs.length > 0
                ? new UnauthAttributes(...unauthAttrs)
                : undefined
    }

    /**
     * Converts the AuthEnvelopedData to an ASN.1 structure.
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

        // AuthEncryptedContentInfo is always present
        values.push(this.authEncryptedContentInfo.toAsn1())

        // Add authAttrs if present
        if (this.authAttrs && this.authAttrs.length > 0) {
            const asn1 = this.authAttrs.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 1 // [1]
            values.push(asn1)
        }

        // MAC is always present
        values.push(this.mac.toAsn1())

        // Add unauthAttrs if present
        if (this.unauthAttrs && this.unauthAttrs.length > 0) {
            const asn1 = this.unauthAttrs.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 2 // [2]
            values.push(asn1)
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    /**
     * Creates an AuthEnvelopedData from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): AuthEnvelopedData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 4) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 4 elements, got ${values.length}`,
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

        // RecipientInfos - required
        const recipientInfosSet = values[currentIndex]
        const recipientInfos = RecipientInfos.fromAsn1(recipientInfosSet)
        currentIndex++

        // AuthEncryptedContentInfo - required
        if (currentIndex >= values.length) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: missing authEncryptedContentInfo',
            )
        }
        const authEncryptedContentInfo = EncryptedContentInfo.fromAsn1(
            values[currentIndex],
        )
        currentIndex++

        // AuthAttrs - optional [1]
        let authAttrs: AuthAttributes | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 1 // [1]
        ) {
            const authAttrsAsn1 = (values[currentIndex] as asn1js.Constructed)
                .valueBlock.value[0]
            authAttrs = AuthAttributes.fromAsn1(authAttrsAsn1)
            currentIndex++
        }

        // MAC - required
        if (currentIndex >= values.length) {
            throw new Asn1ParseError('Invalid ASN.1 structure: missing mac')
        }
        const mac = MessageAuthenticationCode.fromAsn1(values[currentIndex])
        currentIndex++

        // UnauthAttrs - optional [2]
        let unauthAttrs: UnauthAttributes | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 2 // [2]
        ) {
            const unauthAttrsAsn1 = (values[currentIndex] as asn1js.Constructed)
                .valueBlock.value[0]
            unauthAttrs = UnauthAttributes.fromAsn1(unauthAttrsAsn1)
        }

        return new AuthEnvelopedData({
            version,
            recipientInfos,
            authEncryptedContentInfo,
            mac,
            originatorInfo,
            authAttrs,
            unauthAttrs,
        })
    }

    /**
     * Wraps this AuthEnvelopedData in a ContentInfo structure.
     */
    toCms(): ContentInfo {
        return new ContentInfo({
            contentType: OIDs.PKCS7.AUTH_ENVELOPED_DATA,
            content: this,
        })
    }
}
