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
 * Represents a TimeStampReq from RFC 3161.
 *
 * @asn
 * ```asn
 * TimeStampReq ::= SEQUENCE {
 *      version                      INTEGER  { v1(1) },
 *      messageImprint               MessageImprint,
 *      reqPolicy             TSAPolicyId                OPTIONAL,
 *      nonce                 TSANonce                   OPTIONAL,
 *      certReq               BOOLEAN                    DEFAULT FALSE,
 *      extensions            [0] IMPLICIT Extensions    OPTIONAL
 * }
 *
 * TSAPolicyId ::= OBJECT IDENTIFIER
 * TSANonce ::= INTEGER
 * ```
 */
export class TimeStampReq extends PkiBase<TimeStampReq> {
    version: number
    messageImprint: MessageImprint
    reqPolicy?: ObjectIdentifier
    nonce?: Uint8Array // Store as bytes to preserve exact value
    certReq: boolean = false
    extensions?: Extension[]

    constructor(options: {
        version?: number
        messageImprint: MessageImprint
        reqPolicy?: ObjectIdentifierString
        nonce?: Uint8Array
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
     * Converts the TimeStampReq to an ASN.1 structure.
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
     * @param asn1 The ASN.1 structure
     * @returns A TimeStampReq
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
        let nonce: Uint8Array | undefined
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

    static fromDer(der: Uint8Array): TimeStampReq {
        return TimeStampReq.fromAsn1(derToAsn1(der))
    }

    /**
     * Requests a timestamp from a timestamp server.
     *
     * @param options Request options including server URL and authentication
     * @returns Promise resolving to the timestamp response
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

    static fromMessageImprint(messageImprint: MessageImprint): TimeStampReq {
        return new TimeStampReq({ version: 1, messageImprint })
    }

    static create(options: {
        messageImprint: MessageImprint
        version?: number
        reqPolicy?: ObjectIdentifierString
        nonce?: Uint8Array
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
