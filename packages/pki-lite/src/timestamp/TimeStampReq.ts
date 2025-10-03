import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    derToAsn1,
    ObjectIdentifierString,
} from '../core/PkiBase.js'
import { MessageImprint } from './MessageImprint.js'
import { Extension } from '../x509/Extension.js'
import { TimeStampResp } from './TimeStampResp.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Time-Stamp Request structure for RFC 3161 Time-Stamp Protocol.
 *
 * A TimeStampReq is sent to a Time Stamping Authority (TSA) to request a timestamp
 * for data. The request contains a hash of the data to be timestamped (MessageImprint)
 * along with optional parameters like policy requirements and nonce for replay protection.
 *
 * @asn TimeStampReq ::= SEQUENCE {
 *   version         INTEGER  { v1(1) },
 *   messageImprint  MessageImprint,
 *   reqPolicy       TSAPolicyId                OPTIONAL,
 *   nonce           TSANonce                   OPTIONAL,
 *   certReq         BOOLEAN                    DEFAULT FALSE,
 *   extensions      [0] IMPLICIT Extensions    OPTIONAL }
 *
 * TSAPolicyId ::= OBJECT IDENTIFIER
 * TSANonce ::= INTEGER
 *
 * @example
 * ```typescript
 * // Create a timestamp request for some data
 * const data = new TextEncoder().encode("Important document")
 * const algorithm = AlgorithmIdentifier.digestAlgorithm('SHA-256')
 *
 * const messageImprint = new MessageImprint({
 *     hashAlgorithm: algorithm,
 *     hashedMessage: new Uint8Array(await algorithm.digest(data))
 * })
 *
 * const tsReq = new TimeStampReq({
 *     version: 1,
 *     messageImprint: messageImprint,
 *     reqPolicy: "1.3.6.1.4.1.123.456.1", // TSA policy OID
 *     nonce: crypto.getRandomValues(new Uint8Array(16)),
 *     certReq: true // Request TSA certificate in response
 * })
 *
 * // Send to TSA
 * const tsResp = await tsReq.request({
 *     url: 'http://timestamp.example.com/tsa',
 *     timeout: 30000
 * })
 * ```
 *
 * @see RFC 3161 Section 2.4.1 - TSAReq Structure
 */
export class TimeStampReq extends PkiBase<TimeStampReq> {
    /** Version of the TSA request format, currently always 1 */
    version: number

    /** Hash of the data to be timestamped */
    messageImprint: MessageImprint

    /** Optional TSA policy identifier specifying how the timestamp should be created */
    reqPolicy?: ObjectIdentifier

    /** Optional nonce for replay protection, should be unique per request */
    nonce?: Uint8Array<ArrayBuffer> // Store as bytes to preserve exact value

    /** Whether to include the TSA certificate in the response */
    certReq: boolean = false

    /** Optional extensions for additional functionality */
    extensions?: Extension[]

    /**
     * Creates a new TimeStampReq instance.
     *
     * @param options Configuration object for the timestamp request
     * @param options.version Protocol version, defaults to 1
     * @param options.messageImprint Hash imprint of the data to timestamp
     * @param options.reqPolicy Optional TSA policy OID
     * @param options.nonce Optional nonce for replay protection
     * @param options.certReq Whether to request the TSA certificate
     * @param options.extensions Optional request extensions
     *
     * @example
     * ```typescript
     * const request = new TimeStampReq({
     *     messageImprint: messageImprint,
     *     reqPolicy: "1.3.6.1.4.1.123.456.1",
     *     nonce: crypto.getRandomValues(new Uint8Array(8)),
     *     certReq: true
     * })
     * ```
     */
    constructor(options: {
        version?: number
        messageImprint: MessageImprint
        reqPolicy?: ObjectIdentifierString
        nonce?: Uint8Array<ArrayBuffer>
        certReq?: boolean
        extensions?: Extension[]
    }) {
        super()
        const {
            version,
            messageImprint,
            reqPolicy,
            nonce,
            certReq,
            extensions,
        } = options
        this.version = version ?? 1
        this.messageImprint = messageImprint
        this.reqPolicy = reqPolicy
            ? new ObjectIdentifier({ value: reqPolicy })
            : undefined
        this.nonce = nonce
        this.certReq = certReq ?? false
        this.extensions = extensions
    }

    /**
     * Converts the TimeStampReq to its ASN.1 representation.
     *
     * Creates a SEQUENCE containing all the request fields in the proper order
     * according to RFC 3161 specification.
     *
     * @returns ASN.1 structure representing the timestamp request
     *
     * @example
     * ```typescript
     * const asn1 = tsReq.toAsn1()
     * const der = asn1.toBER(false) // Convert to DER for transmission
     * ```
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            this.messageImprint.toAsn1(),
        ]

        if (this.reqPolicy) {
            values.push(this.reqPolicy.toAsn1())
        }

        if (this.nonce) {
            values.push(new asn1js.Integer({ valueHex: this.nonce }))
        }

        if (this.certReq) {
            values.push(new asn1js.Boolean({ value: this.certReq }))
        }

        if (this.extensions && this.extensions.length > 0) {
            const extensionsArray = this.extensions.map((ext) => ext.toAsn1())
            // Extensions are [0] IMPLICIT
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                        isConstructed: true, // For EXPLICIT Extensions
                    },
                    value: [
                        new asn1js.Sequence({
                            value: extensionsArray,
                        }),
                    ],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    /**
     * Creates a TimeStampReq from an ASN.1 structure.
     *
     * Parses the ASN.1 SEQUENCE and extracts all optional and required fields
     * according to RFC 3161 specification.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed TimeStampReq object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     *
     * @example
     * ```typescript
     * const asn1 = derToAsn1(requestBytes)
     * const request = TimeStampReq.fromAsn1(asn1)
     *
     * console.log(request.version) // Should be 1
     * console.log(request.messageImprint.hashAlgorithm)
     * console.log(request.certReq) // Certificate requested
     * ```
     */
    static fromAsn1(asn1: Asn1BaseBlock): TimeStampReq {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 2 elements',
            )
        }

        // Version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for version',
            )
        }
        const version = values[0].valueBlock.valueDec
        if (version !== 1) {
            throw new Asn1ParseError(
                `Unsupported TimeStampReq version: ${version}`,
            )
        }

        // MessageImprint
        const messageImprint = MessageImprint.fromAsn1(values[1])

        // Parse optional fields
        let reqPolicy: ObjectIdentifier | undefined
        let nonce: Uint8Array<ArrayBuffer> | undefined
        let certReq = false
        let extensions: Extension[] | undefined

        for (let i = 2; i < values.length; i++) {
            const value = values[i]

            if (value instanceof asn1js.ObjectIdentifier) {
                reqPolicy = new ObjectIdentifier({
                    value: value.valueBlock.toString(),
                })
            } else if (value instanceof asn1js.Integer) {
                nonce = new Uint8Array(value.valueBlock.valueHexView)
            } else if (value instanceof asn1js.Boolean) {
                certReq = value.valueBlock.value
            } else if (
                value instanceof asn1js.Constructed &&
                value.idBlock.tagClass === 3 && // CONTEXT-SPECIFIC
                value.idBlock.tagNumber === 0 // [0]
            ) {
                // Parse extensions from [0] EXPLICIT Extensions
                if (value.valueBlock.value.length > 0) {
                    const extensionsSeq = value.valueBlock.value[0]
                    if (extensionsSeq instanceof asn1js.Sequence) {
                        extensions = extensionsSeq.valueBlock.value.map((ext) =>
                            Extension.fromAsn1(ext),
                        )
                    }
                }
            }
        }

        return new TimeStampReq({
            version: 1,
            messageImprint,
            reqPolicy,
            nonce,
            certReq,
            extensions,
        })
    }

    /**
     * Creates a TimeStampReq from DER-encoded bytes.
     *
     * @param der The DER-encoded timestamp request bytes
     * @returns The parsed TimeStampReq
     * @throws Error if DER parsing fails
     */
    static fromDer(der: Uint8Array<ArrayBuffer>): TimeStampReq {
        return TimeStampReq.fromAsn1(derToAsn1(der))
    }

    /**
     * Sends the timestamp request to a Time Stamping Authority (TSA).
     *
     * This method handles the HTTP protocol for communicating with RFC 3161
     * compliant TSA servers. It sends the request as application/timestamp-query
     * and expects an application/timestamp-reply response.
     *
     * @param options Request configuration
     * @param options.url TSA server URL
     * @param options.username Optional basic auth username
     * @param options.password Optional basic auth password
     * @param options.timeout Optional request timeout in milliseconds
     * @param options.otherRequestOptions Additional fetch options
     * @returns Promise resolving to the timestamp response
     * @throws Error if the HTTP request fails or TSA returns an error
     *
     * @example
     * ```typescript
     * // Simple request to public TSA
     * const response = await tsReq.request({
     *     url: 'http://timestamp.digicert.com'
     * })
     *
     * // Authenticated request with timeout
     * const response = await tsReq.request({
     *     url: 'https://tsa.example.com/tsa',
     *     username: 'user',
     *     password: 'pass',
     *     timeout: 30000
     * })
     *
     * if (response.status.status === 0) { // Granted
     *     console.log('Timestamp obtained:', response.timeStampToken)
     * } else {
     *     console.error('Timestamp request failed:', response.status.failInfo)
     * }
     * ```
     */
    async request(options: {
        url: string
        username?: string
        password?: string
        timeout?: number
        otherRequestOptions?: RequestInit
    }): Promise<TimeStampResp> {
        const tsqDer = this.toDer()

        const headers: Record<string, string> = {
            'Content-Type': 'application/timestamp-query',
            Accept: 'application/timestamp-reply',
            'Content-Length': tsqDer.byteLength.toString(),
        }

        if (options.username && options.password) {
            const credentials = btoa(`${options.username}:${options.password}`)
            headers['Authorization'] = `Basic ${credentials}`
        }

        const response = await fetch(options.url, {
            method: 'POST',
            headers: headers,
            body: tsqDer,
            mode: 'no-cors',
            ...options.otherRequestOptions,
        })

        if (!response.ok) {
            const errorText = await response.text()
            throw new Error(
                `TSA request failed (${response.status}): ${errorText}`,
            )
        }

        const tsrBuffer = await response.arrayBuffer()
        const tsrAsn1 = derToAsn1(tsrBuffer)

        return TimeStampResp.fromAsn1(tsrAsn1)
    }

    /**
     * Creates a simple TimeStampReq from a MessageImprint.
     *
     * Convenience method for creating a basic timestamp request with default settings.
     *
     * @param messageImprint The message imprint to timestamp
     * @returns A new TimeStampReq with version 1 and the given message imprint
     *
     * @example
     * ```typescript
     * const request = TimeStampReq.fromMessageImprint(messageImprint)
     * ```
     */
    static fromMessageImprint(messageImprint: MessageImprint): TimeStampReq {
        return new TimeStampReq({ version: 1, messageImprint })
    }

    /**
     * Creates a TimeStampReq with the specified options.
     *
     * Alternative constructor method that provides more explicit parameter naming.
     *
     * @param options Request configuration
     * @returns A new TimeStampReq instance
     *
     * @example
     * ```typescript
     * const request = TimeStampReq.create({
     *     messageImprint: messageImprint,
     *     reqPolicy: "1.3.6.1.4.1.123.456.1",
     *     nonce: crypto.getRandomValues(new Uint8Array(16)),
     *     certReq: true
     * })
     * ```
     */
    static create(options: {
        messageImprint: MessageImprint
        version?: number
        reqPolicy?: ObjectIdentifierString
        nonce?: Uint8Array<ArrayBuffer>
        certReq?: boolean
        extensions?: Extension[]
    }): TimeStampReq {
        return new TimeStampReq({
            version: options.version ?? 1,
            messageImprint: options.messageImprint,
            reqPolicy: options.reqPolicy,
            nonce: options.nonce,
            certReq: options.certReq,
            extensions: options.extensions,
        })
    }
}
