import { writeFileSync } from 'fs'
import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * PKI Status values from RFC 3161
 */
export const PKIStatus = {
    GRANTED: 0,
    GRANTED_WITH_MODS: 1,
    REJECTION: 2,
    WAITING: 3,
    REVOCATION_WARNING: 4,
    REVOCATION_NOTIFICATION: 5,
} as const

export type PKIStatus = (typeof PKIStatus)[keyof typeof PKIStatus]

/**
 * PKI Failure Info values from RFC 3161
 */
export const PKIFailureInfo = {
    BAD_ALG: 0,
    BAD_REQUEST: 2,
    BAD_DATA_FORMAT: 5,
    TIME_NOT_AVAILABLE: 14,
    UNACCEPTED_POLICY: 15,
    UNACCEPTED_EXTENSION: 16,
    ADD_INFO_NOT_AVAILABLE: 17,
    SYSTEM_FAILURE: 25,
} as const

export type PKIFailureInfo =
    (typeof PKIFailureInfo)[keyof typeof PKIFailureInfo]

/**
 * Represents a PKIFreeText from RFC 3161.
 *
 * @asn
 * ```asn
 * PKIFreeText ::= SEQUENCE SIZE (1..255) OF UTF8String
 * ```
 */
export class PKIFreeText extends PkiBase<PKIFreeText> {
    texts: string[]

    constructor(options: { texts: string[] }) {
        super()
        if (options.texts.length === 0 || options.texts.length > 255) {
            throw new Error('PKIFreeText must contain 1-255 text entries')
        }
        this.texts = options.texts
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: this.texts.map(
                (text) => new asn1js.Utf8String({ value: text }),
            ),
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PKIFreeText {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const texts = asn1.valueBlock.value.map((value) => {
            if (!(value instanceof asn1js.Utf8String)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected UTF8String in PKIFreeText',
                )
            }
            return value.valueBlock.value
        })

        return new PKIFreeText({ texts })
    }
}

/**
 * Represents a PKIStatus from RFC 3161.
 *
 * @asn
 * ```asn
 * PKIStatus ::= INTEGER {
 *     granted                (0),
 *     grantedWithMods        (1),
 *     rejection              (2),
 *     waiting                (3),
 *     revocationWarning      (4),
 *     revocationNotification (5)
 * }
 * ```
 */
export class PKIStatusInfo extends PkiBase<PKIStatusInfo> {
    status: PKIStatus
    statusString?: PKIFreeText
    failInfo?: PKIFailureInfo

    constructor(options: {
        status: PKIStatus
        statusString?: PKIFreeText
        failInfo?: PKIFailureInfo
    }) {
        super()
        this.status = options.status
        this.statusString = options.statusString
        this.failInfo = options.failInfo
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.status }),
        ]

        if (this.statusString) {
            values.push(this.statusString.toAsn1())
        }

        if (this.failInfo !== undefined) {
            // PKIFailureInfo is a BIT STRING
            const failInfoBitString = new asn1js.BitString({
                valueHex: new Uint8Array([this.failInfo]),
            })
            values.push(failInfoBitString)
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PKIStatusInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length === 0) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 1 element',
            )
        }

        // Status
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for status',
            )
        }
        const status = values[0].valueBlock.valueDec as PKIStatus

        // Optional statusString
        let statusString: PKIFreeText | undefined
        let failInfo: PKIFailureInfo | undefined

        for (let i = 1; i < values.length; i++) {
            const value = values[i]

            if (value instanceof asn1js.Sequence) {
                statusString = PKIFreeText.fromAsn1(value)
            } else if (value instanceof asn1js.BitString) {
                const failInfoBytes = new Uint8Array(
                    value.valueBlock.valueHexView,
                )
                if (failInfoBytes.length > 0) {
                    failInfo = failInfoBytes[0] as PKIFailureInfo
                }
            }
        }

        return new PKIStatusInfo({ status, statusString, failInfo })
    }

    /**
     * Check if the status indicates success
     */
    isSuccess(): boolean {
        return (
            this.status === PKIStatus.GRANTED ||
            this.status === PKIStatus.GRANTED_WITH_MODS
        )
    }

    /**
     * Get a human-readable status description
     */
    getStatusDescription(): string {
        switch (this.status) {
            case PKIStatus.GRANTED:
                return 'granted'
            case PKIStatus.GRANTED_WITH_MODS:
                return 'granted with modifications'
            case PKIStatus.REJECTION:
                return 'rejection'
            case PKIStatus.WAITING:
                return 'waiting'
            case PKIStatus.REVOCATION_WARNING:
                return 'revocation warning'
            case PKIStatus.REVOCATION_NOTIFICATION:
                return 'revocation notification'
            default:
                return `unknown status (${this.status})`
        }
    }
}

/**
 * Represents a TimeStampResp from RFC 3161.
 *
 * @asn
 * ```asn
 * TimeStampResp ::= SEQUENCE  {
 *      status                  PKIStatus,
 *      timeStampToken          TimeStampToken           OPTIONAL
 * }
 *
 * TimeStampToken ::= ContentInfo
 * ```
 */
export class TimeStampResp extends PkiBase<TimeStampResp> {
    status: PKIStatusInfo
    timeStampToken?: ContentInfo

    constructor(options: {
        status: PKIStatusInfo
        timeStampToken?: ContentInfo
    }) {
        super()

        this.status = options.status
        this.timeStampToken = options.timeStampToken
    }

    /**
     * Converts the TimeStampResp to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [this.status.toAsn1()]

        if (this.timeStampToken) {
            values.push(this.timeStampToken.toAsn1())
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    /**
     * Creates a TimeStampResp from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A TimeStampResp
     */
    static fromAsn1(asn1: Asn1BaseBlock): TimeStampResp {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 1 element',
            )
        }

        // Status
        const status = PKIStatusInfo.fromAsn1(values[0])

        // Optional timeStampToken
        let timeStampToken: ContentInfo | undefined
        if (values.length > 1) {
            timeStampToken = ContentInfo.fromAsn1(values[1])
        }

        return new TimeStampResp({ status, timeStampToken })
    }

    /**
     * Check if the response indicates success
     */
    isSuccess(): boolean {
        return this.status.isSuccess()
    }

    /**
     * Get the timestamp token as DER bytes
     */
    getTimeStampTokenDer(): Uint8Array {
        if (!this.timeStampToken) {
            throw new Error('No timestamp token available')
        }

        return this.timeStampToken.toDer()
    }
}
