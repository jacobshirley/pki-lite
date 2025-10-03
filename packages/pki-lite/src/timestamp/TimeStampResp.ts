import { writeFileSync } from 'fs'
import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * PKI Status values as defined in RFC 3161.
 * These values indicate the result of a timestamp request.
 *
 * @example
 * ```typescript
 * if (response.status.status === PKIStatus.GRANTED) {
 *     console.log('Timestamp successfully granted')
 * } else if (response.status.status === PKIStatus.REJECTION) {
 *     console.log('Timestamp request rejected')
 * }
 * ```
 */
export const PKIStatus = {
    /** Request granted successfully */
    GRANTED: 0,
    /** Request granted with some modifications */
    GRANTED_WITH_MODS: 1,
    /** Request rejected */
    REJECTION: 2,
    /** Request is waiting for processing */
    WAITING: 3,
    /** Warning about certificate revocation */
    REVOCATION_WARNING: 4,
    /** Notification about certificate revocation */
    REVOCATION_NOTIFICATION: 5,
} as const

export type PKIStatus = (typeof PKIStatus)[keyof typeof PKIStatus]

/**
 * PKI Failure Info bit flags as defined in RFC 3161.
 * These provide specific information about why a request failed.
 *
 * @example
 * ```typescript
 * if (response.status.failInfo === PKIFailureInfo.BAD_ALG) {
 *     console.log('Unrecognized or unsupported algorithm')
 * }
 * ```
 */
export const PKIFailureInfo = {
    /** Unrecognized or unsupported algorithm identifier */
    BAD_ALG: 0,
    /** Transaction not permitted or supported */
    BAD_REQUEST: 2,
    /** The data submitted has the wrong format */
    BAD_DATA_FORMAT: 5,
    /** The TSA's time source is not available */
    TIME_NOT_AVAILABLE: 14,
    /** The requested TSA policy is not supported */
    UNACCEPTED_POLICY: 15,
    /** The requested extension is not supported */
    UNACCEPTED_EXTENSION: 16,
    /** The additional information requested could not be understood or is not available */
    ADD_INFO_NOT_AVAILABLE: 17,
    /** The request cannot be handled due to system failure */
    SYSTEM_FAILURE: 25,
} as const

export type PKIFailureInfo =
    (typeof PKIFailureInfo)[keyof typeof PKIFailureInfo]

/**
 * Free-form text information from the TSA.
 *
 * PKIFreeText provides human-readable information about the timestamp request
 * processing, such as error details or warnings.
 *
 * @asn PKIFreeText ::= SEQUENCE SIZE (1..255) OF UTF8String
 *
 * @example
 * ```typescript
 * const freeText = new PKIFreeText({
 *     texts: ['Certificate will expire soon', 'Consider renewal']
 * })
 * ```
 */
export class PKIFreeText extends PkiBase<PKIFreeText> {
    /** Array of UTF-8 text strings, must contain 1-255 entries */
    texts: string[]

    /**
     * Creates a new PKIFreeText instance.
     *
     * @param options Configuration object
     * @param options.texts Array of text strings (1-255 entries)
     * @throws Error if texts array is empty or contains more than 255 entries
     */
    constructor(options: { texts: string[] }) {
        super()
        if (options.texts.length === 0 || options.texts.length > 255) {
            throw new Error('PKIFreeText must contain 1-255 text entries')
        }
        this.texts = options.texts
    }

    /**
     * Converts the PKIFreeText to its ASN.1 representation.
     *
     * @returns ASN.1 SEQUENCE of UTF8String values
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: this.texts.map(
                (text) => new asn1js.Utf8String({ value: text }),
            ),
        })
    }

    /**
     * Creates a PKIFreeText from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed PKIFreeText object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     */
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
 * Status information for a timestamp request/response.
 *
 * PKIStatusInfo provides detailed information about the processing of a timestamp
 * request, including success/failure status, optional descriptive text, and
 * specific failure reasons when applicable.
 *
 * @asn PKIStatusInfo ::= SEQUENCE {
 *   status       PKIStatus,
 *   statusString PKIFreeText     OPTIONAL,
 *   failInfo     PKIFailureInfo  OPTIONAL }
 *
 * @example
 * ```typescript
 * // Success status
 * const successStatus = new PKIStatusInfo({
 *     status: PKIStatus.GRANTED
 * })
 *
 * // Failure status with details
 * const failureStatus = new PKIStatusInfo({
 *     status: PKIStatus.REJECTION,
 *     statusString: new PKIFreeText({ texts: ['Invalid algorithm'] }),
 *     failInfo: PKIFailureInfo.BAD_ALG
 * })
 *
 * if (statusInfo.isSuccess()) {
 *     console.log('Request was successful')
 * } else {
 *     console.log('Request failed:', statusInfo.getStatusDescription())
 * }
 * ```
 */
export class PKIStatusInfo extends PkiBase<PKIStatusInfo> {
    /** The status code indicating success or failure */
    status: PKIStatus

    /** Optional human-readable status description */
    statusString?: PKIFreeText

    /** Optional specific failure information */
    failInfo?: PKIFailureInfo

    /**
     * Creates a new PKIStatusInfo instance.
     *
     * @param options Configuration object
     * @param options.status The PKI status code
     * @param options.statusString Optional descriptive text
     * @param options.failInfo Optional failure information
     */
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

    /**
     * Converts the PKIStatusInfo to its ASN.1 representation.
     *
     * @returns ASN.1 SEQUENCE containing status and optional fields
     */
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

    /**
     * Creates a PKIStatusInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed PKIStatusInfo object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     */
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
    getTimeStampTokenDer(): Uint8Array<ArrayBuffer> {
        if (!this.timeStampToken) {
            throw new Error('No timestamp token available')
        }

        return this.timeStampToken.toDer()
    }
}
