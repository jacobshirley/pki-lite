import { Asn1BaseBlock, asn1js, PkiBase, PkiSet } from '../core/PkiBase.js'
import { RecipientInfo } from './recipients/RecipientInfo.js'
import { OriginatorInfo } from './recipients/OriginatorInfo.js'
import { Attribute } from '../x509/Attribute.js'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'
import { CMSVersion } from './CMSVersion.js'
import { ContentInfo } from './ContentInfo.js'
import { OIDs } from '../core/OIDs.js'
import {
    DigestAlgorithmIdentifier,
    AlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of authenticated attributes.
 *
 * @asn
 * ```asn
 * AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
class AuthAttributes extends PkiSet<Attribute> {
    static fromAsn1(asn1: Asn1BaseBlock): AuthAttributes {
        if (!(asn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for AuthAttributes',
            )
        }

        const attributes = asn1.valueBlock.value.map((attrAsn1) =>
            Attribute.fromAsn1(attrAsn1),
        )

        return new AuthAttributes(...attributes)
    }
}

/**
 * Represents a set of unauthenticated attributes.
 *
 * @asn
 * ```asn
 * UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
class UnauthAttributes extends PkiSet<Attribute> {
    static fromAsn1(asn1: Asn1BaseBlock): UnauthAttributes {
        if (!(asn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for UnauthAttributes',
            )
        }

        const attributes = asn1.valueBlock.value.map((attrAsn1) =>
            Attribute.fromAsn1(attrAsn1),
        )

        return new UnauthAttributes(...attributes)
    }
}

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
 * Authenticated Data
 *
 * @asn
 * ```asn
 * AuthenticatedData ::= SEQUENCE {
 *     version CMSVersion,
 *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos RecipientInfos,
 *     macAlgorithm MessageAuthenticationCodeAlgorithm,
 *     digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
 *     encapContentInfo EncapsulatedContentInfo,
 *     authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
 *     mac MessageAuthenticationCode,
 *     unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL
 * }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * ```
 */
export class AuthenticatedData extends PkiBase<AuthenticatedData> {
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
     * The version of the AuthenticatedData structure.
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
     * The MAC algorithm used for authentication.
     */
    macAlgorithm: AlgorithmIdentifier

    /**
     * Optional digest algorithm.
     */
    digestAlgorithm?: DigestAlgorithmIdentifier

    /**
     * The encapsulated content information.
     */
    encapContentInfo: EncapsulatedContentInfo

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
     * Creates a new AuthenticatedData instance.
     */
    constructor(options: {
        version: CMSVersion
        recipientInfos: RecipientInfo[]
        macAlgorithm: AlgorithmIdentifier
        encapContentInfo: EncapsulatedContentInfo
        mac: Uint8Array
        originatorInfo?: OriginatorInfo
        digestAlgorithm?: DigestAlgorithmIdentifier
        authAttrs?: Attribute[]
        unauthAttrs?: Attribute[]
    }) {
        super()

        const {
            version,
            recipientInfos,
            macAlgorithm,
            encapContentInfo,
            mac,
            originatorInfo,
            digestAlgorithm,
            authAttrs,
            unauthAttrs,
        } = options

        this.version = version
        this.recipientInfos = new RecipientInfos(...recipientInfos)
        this.macAlgorithm = macAlgorithm
        this.encapContentInfo = encapContentInfo
        this.mac = new MessageAuthenticationCode(mac)
        this.originatorInfo = originatorInfo
        this.digestAlgorithm = digestAlgorithm
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
     * Converts the AuthenticatedData to an ASN.1 structure.
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

        // MAC algorithm is always present
        values.push(this.macAlgorithm.toAsn1())

        // Add digestAlgorithm if present
        if (this.digestAlgorithm) {
            const asn1 = this.digestAlgorithm.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 1 // [1]
            values.push(asn1)
        }

        // EncapsulatedContentInfo is always present
        values.push(this.encapContentInfo.toAsn1())

        // Add authAttrs if present
        if (this.authAttrs && this.authAttrs.length > 0) {
            const asn1 = this.authAttrs.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 2 // [2]
            values.push(asn1)
        }

        // MAC is always present
        values.push(this.mac.toAsn1())

        // Add unauthAttrs if present
        if (this.unauthAttrs && this.unauthAttrs.length > 0) {
            const asn1 = this.unauthAttrs.toAsn1()
            asn1.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            asn1.idBlock.tagNumber = 3 // [3]
            values.push(asn1)
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    /**
     * Creates an AuthenticatedData from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): AuthenticatedData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 5) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 5 elements, got ${values.length}`,
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

        // MacAlgorithm - required
        const macAlgorithm = AlgorithmIdentifier.fromAsn1(values[currentIndex])
        currentIndex++

        // DigestAlgorithm - optional [1]
        let digestAlgorithm: DigestAlgorithmIdentifier | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 1 // [1]
        ) {
            const digestAlgorithmAsn1 = (
                values[currentIndex] as asn1js.Constructed
            ).valueBlock.value[0]
            digestAlgorithm =
                DigestAlgorithmIdentifier.fromAsn1(digestAlgorithmAsn1)
            currentIndex++
        }

        // EncapsulatedContentInfo - required
        if (currentIndex >= values.length) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: missing encapsulatedContentInfo',
            )
        }
        const encapContentInfo = EncapsulatedContentInfo.fromAsn1(
            values[currentIndex],
        )
        currentIndex++

        // AuthAttrs - optional [2]
        let authAttrs: AuthAttributes | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 2 // [2]
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

        // UnauthAttrs - optional [3]
        let unauthAttrs: UnauthAttributes | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex] instanceof asn1js.Constructed &&
            values[currentIndex].idBlock.tagClass === 3 && // CONTEXT_SPECIFIC
            values[currentIndex].idBlock.tagNumber === 3 // [3]
        ) {
            const unauthAttrsAsn1 = (values[currentIndex] as asn1js.Constructed)
                .valueBlock.value[0]
            unauthAttrs = UnauthAttributes.fromAsn1(unauthAttrsAsn1)
        }

        return new AuthenticatedData({
            version,
            recipientInfos,
            macAlgorithm,
            encapContentInfo,
            mac,
            originatorInfo,
            digestAlgorithm,
            authAttrs,
            unauthAttrs,
        })
    }

    /**
     * Wraps this AuthenticatedData in a ContentInfo structure.
     */
    toCms(): ContentInfo {
        return new ContentInfo({
            contentType: OIDs.PKCS7.AUTHENTICATED_DATA,
            content: this,
        })
    }
}
