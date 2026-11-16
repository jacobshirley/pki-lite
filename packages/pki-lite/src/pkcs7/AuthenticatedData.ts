import {
    Asn1Node,
    der,
    PkiBase,
    PkiSet,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
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
import { MessageAuthenticationCode } from './MessageAuthenticationCode.js'
/**
 * Represents a set of authenticated attributes.
 *
 * @asn
 * ```asn
 * AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
class AuthAttributes extends PkiSet<Attribute> {
    static fromAsn1(asn1: Asn1Node): AuthAttributes {
        if (!asn1.is(UniversalTag.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for AuthAttributes',
            )
        }

        const attributes = asn1.children.map((attrAsn1) =>
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
    static fromAsn1(asn1: Asn1Node): UnauthAttributes {
        if (!asn1.is(UniversalTag.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for UnauthAttributes',
            )
        }

        const attributes = asn1.children.map((attrAsn1) =>
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
    /**
     * Encodes each RecipientInfo through its CHOICE so that kari [1], kekri [2],
     * pwri [3] and ori [4] get their context tag (a bare SEQUENCE would be read as
     * a KeyTransRecipientInfo).
     */
    toAsn1(): Asn1Node {
        return der.set(this.map((recipient) => RecipientInfo.toAsn1(recipient)))
    }

    static fromAsn1(asn1: Asn1Node): RecipientInfos {
        if (!asn1.is(UniversalTag.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for RecipientInfos',
            )
        }

        const recipients = asn1.children.map((recAsn1) =>
            RecipientInfo.fromAsn1(recAsn1),
        )

        return new RecipientInfos(...recipients)
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
        mac: Uint8Array<ArrayBuffer> | MessageAuthenticationCode
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
        this.mac = new MessageAuthenticationCode({ bytes: mac })
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
    toAsn1(): Asn1Node {
        const values = []

        // Version is always present
        values.push(der.integer(this.version))

        // Add originatorInfo if present
        if (this.originatorInfo) {
            const asn1 = this.originatorInfo.toAsn1().implicit(0) // [0] IMPLICIT
            values.push(asn1)
        }

        // RecipientInfos is always present
        values.push(this.recipientInfos.toAsn1())

        // MAC algorithm is always present
        values.push(this.macAlgorithm.toAsn1())

        // Add digestAlgorithm if present
        if (this.digestAlgorithm) {
            const asn1 = this.digestAlgorithm.toAsn1().implicit(1) // [1] IMPLICIT
            values.push(asn1)
        }

        // EncapsulatedContentInfo is always present
        values.push(this.encapContentInfo.toAsn1())

        // Add authAttrs if present
        if (this.authAttrs && this.authAttrs.length > 0) {
            const asn1 = this.authAttrs.toAsn1().implicit(2) // [2] IMPLICIT
            values.push(asn1)
        }

        // MAC is always present
        values.push(this.mac.toAsn1())

        // Add unauthAttrs if present
        if (this.unauthAttrs && this.unauthAttrs.length > 0) {
            const asn1 = this.unauthAttrs.toAsn1().implicit(3) // [3] IMPLICIT
            values.push(asn1)
        }

        return der.sequence(values)
    }

    /**
     * Creates an AuthenticatedData from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): AuthenticatedData {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.children
        if (values.length < 5) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected at least 5 elements, got ${values.length}`,
            )
        }

        let currentIndex = 0

        // Version - always first
        if (!values[currentIndex]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }

        const version = der.readNumber(values[currentIndex])

        currentIndex++

        // OriginatorInfo - optional [0]
        let originatorInfo: OriginatorInfo | undefined
        if (
            currentIndex < values.length &&
            values[currentIndex]?.constructed &&
            values[currentIndex].tagClass === TagClass.Context && // CONTEXT_SPECIFIC
            values[currentIndex].tag === 0 // [0]
        ) {
            const originatorInfoAsn1 = values[currentIndex].children[0]
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
            values[currentIndex]?.constructed &&
            values[currentIndex].tagClass === TagClass.Context && // CONTEXT_SPECIFIC
            values[currentIndex].tag === 1 // [1]
        ) {
            const digestAlgorithmAsn1 = values[currentIndex].children[0]
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
            values[currentIndex]?.constructed &&
            values[currentIndex].tagClass === TagClass.Context && // CONTEXT_SPECIFIC
            values[currentIndex].tag === 2 // [2]
        ) {
            const authAttrsAsn1 = values[currentIndex].children[0]
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
            values[currentIndex]?.constructed &&
            values[currentIndex].tagClass === TagClass.Context && // CONTEXT_SPECIFIC
            values[currentIndex].tag === 3 // [3]
        ) {
            const unauthAttrsAsn1 = values[currentIndex].children[0]
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
