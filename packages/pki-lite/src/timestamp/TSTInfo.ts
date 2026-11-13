import {
    Asn1Node,
    der,
    derToAsn1,
    ObjectIdentifierString,
    PkiBase,
    UniversalTag,
} from '../core/PkiBase.js'
import { MessageImprint } from './MessageImprint.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Extension } from '../x509/Extension.js'
import { GeneralName } from '../x509/GeneralName.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import {
    implicitSequenceOf,
    implicitTag,
    isContextTag,
} from '../core/tagging.js'

/**
 * Accuracy structure for RFC 3161 Time-Stamp Protocol.
 *
 * Specifies the accuracy of the time in the timestamp token.
 * All fields are optional, but at least one should be present.
 *
 * @asn
 * ```asn
 * Accuracy ::= SEQUENCE {
 *     seconds        INTEGER           OPTIONAL,
 *     millis     [0] INTEGER  (1..999) OPTIONAL,
 *     micros     [1] INTEGER  (1..999) OPTIONAL  }
 * ```
 *
 * @see RFC 3161 Section 2.4.2 - TSTInfo Structure
 */
export class Accuracy extends PkiBase<Accuracy> {
    /** Accuracy in seconds, optional */
    seconds?: number

    /** Accuracy in milliseconds (1-999), optional */
    millis?: number

    /** Accuracy in microseconds (1-999), optional */
    micros?: number

    /**
     * Creates a new Accuracy instance.
     *
     * @param options Configuration object for accuracy values
     * @param options.seconds Optional accuracy in seconds
     * @param options.millis Optional accuracy in milliseconds (1-999)
     * @param options.micros Optional accuracy in microseconds (1-999)
     * @throws Error if millis or micros are out of valid range
     *
     * @example
     * ```typescript
     * const accuracy = new Accuracy({
     *     seconds: 1,
     *     millis: 500,
     *     micros: 250
     * })
     * ```
     */
    constructor(options: {
        seconds?: number
        millis?: number
        micros?: number
    }) {
        super()

        const { seconds, millis, micros } = options

        if (millis !== undefined && (millis < 1 || millis > 999)) {
            throw new Error('millis must be between 1 and 999')
        }
        if (micros !== undefined && (micros < 1 || micros > 999)) {
            throw new Error('micros must be between 1 and 999')
        }

        this.seconds = seconds
        this.millis = millis
        this.micros = micros
    }

    /**
     * Converts the Accuracy to its ASN.1 representation.
     *
     * @returns ASN.1 SEQUENCE containing the accuracy fields
     *
     * @example
     * ```typescript
     * const asn1 = accuracy.toAsn1()
     * const der = asn1.encode()
     * ```
     */
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        if (this.seconds !== undefined) {
            values.push(der.integer(this.seconds))
        }

        // the RFC 3161 module has IMPLICIT TAGS: millis/micros are [0]/[1] IMPLICIT INTEGER
        if (this.millis !== undefined) {
            values.push(implicitTag(der.integer(this.millis), 0))
        }

        if (this.micros !== undefined) {
            values.push(implicitTag(der.integer(this.micros), 1))
        }

        return der.sequence(values)
    }

    /**
     * Creates an Accuracy from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed Accuracy object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     *
     * @example
     * ```typescript
     * const asn1 = derToAsn1(accuracyBytes)
     * const accuracy = Accuracy.fromAsn1(asn1)
     * console.log(accuracy.seconds, accuracy.millis, accuracy.micros)
     * ```
     */
    static fromAsn1(asn1: Asn1Node): Accuracy {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        let seconds: number | undefined
        let millis: number | undefined
        let micros: number | undefined

        for (const value of asn1.children) {
            // check the tag first: an in-memory [n] IMPLICIT INTEGER is still an Integer
            if (isContextTag(value, 0)) {
                millis = Accuracy.taggedInteger(value)
            } else if (isContextTag(value, 1)) {
                micros = Accuracy.taggedInteger(value)
            } else if (value.is(UniversalTag.Integer)) {
                seconds = der.readNumber(value)
            }
        }

        return new Accuracy({ seconds, millis, micros })
    }

    /** The value of an [n] IMPLICIT INTEGER (or, as older pki-lite wrote it, EXPLICIT) */
    private static taggedInteger(value: Asn1Node): number {
        if (value.is(UniversalTag.Integer)) return der.readNumber(value)
        if (value?.constructed) {
            const inner = value.children[0]
            if (!inner.is(UniversalTag.Integer)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected INTEGER in context-specific tag',
                )
            }
            return der.readNumber(inner)
        }
        // [n] IMPLICIT INTEGER
        return der.readNumber(value.retag(UniversalTag.Integer))
    }
}

/**
 * TSTInfo structure for RFC 3161 Time-Stamp Protocol.
 *
 * The TSTInfo is the core content of a timestamp token. It contains the
 * actual timestamp along with the hashed data and policy information.
 * This structure is encapsulated within a SignedData content type.
 *
 * @asn
 * ```asn
 * TSTInfo ::= SEQUENCE  {
 *     version                      INTEGER  { v1(1) },
 *     policy                       TSAPolicyId,
 *     messageImprint               MessageImprint,
 *       -- MUST have the same value as the similar field in
 *       -- TimeStampReq
 *     serialNumber                 INTEGER,
 *      -- Time-Stamping users MUST be ready to accommodate integers
 *      -- up to 160 bits.
 *     genTime                      GeneralizedTime,
 *     accuracy                     Accuracy                 OPTIONAL,
 *     ordering                     BOOLEAN             DEFAULT FALSE,
 *     nonce                        INTEGER                  OPTIONAL,
 *       -- MUST be present if the similar field was present
 *       -- in TimeStampReq.  In that case it MUST have the same value.
 *     tsa                          [0] GeneralName          OPTIONAL,
 *     extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
 *
 * TSAPolicyId ::= OBJECT IDENTIFIER
 * ```
 *
 * @see RFC 3161 Section 2.4.2 - TSTInfo Structure
 */
export class TSTInfo extends PkiBase<TSTInfo> {
    /** Version of the TSTInfo format, currently always 1 */
    version: number

    /** TSA policy under which the timestamp was issued */
    policy: ObjectIdentifier

    /** Hash of the data that was timestamped */
    messageImprint: MessageImprint

    /** Unique serial number for this timestamp */
    serialNumber: Uint8Array<ArrayBuffer>

    /** Time at which the timestamp was generated */
    genTime: Date

    /** Optional accuracy of the timestamp */
    accuracy?: Accuracy

    /** Whether timestamps are ordered (default false) */
    ordering: boolean = false

    /** Optional nonce from the request */
    nonce?: Uint8Array<ArrayBuffer>

    /** Optional TSA identity */
    tsa?: GeneralName

    /** Optional extensions */
    extensions?: Extension[]

    /**
     * Creates a new TSTInfo instance.
     *
     * @param options Configuration object for the timestamp info
     * @param options.version Protocol version, defaults to 1
     * @param options.policy TSA policy OID
     * @param options.messageImprint Hash imprint that was timestamped
     * @param options.serialNumber Unique serial number (up to 160 bits)
     * @param options.genTime Generation time of the timestamp
     * @param options.accuracy Optional accuracy specification
     * @param options.ordering Whether timestamps are ordered
     * @param options.nonce Optional nonce (must match request if present)
     * @param options.tsa Optional TSA identity
     * @param options.extensions Optional extensions
     *
     * @example
     * ```typescript
     * const tstInfo = new TSTInfo({
     *     policy: "1.3.6.1.4.1.123.456.1",
     *     messageImprint: messageImprint,
     *     serialNumber: new Uint8Array([1, 2, 3, 4]),
     *     genTime: new Date(),
     *     accuracy: new Accuracy({ seconds: 1 }),
     *     ordering: false
     * })
     * ```
     */
    constructor(options: {
        version?: number
        policy: ObjectIdentifierString
        messageImprint: MessageImprint
        serialNumber: Uint8Array<ArrayBuffer>
        genTime: Date
        accuracy?: Accuracy
        ordering?: boolean
        nonce?: Uint8Array<ArrayBuffer>
        tsa?: GeneralName
        extensions?: Extension[]
    }) {
        super()

        const {
            version,
            policy,
            messageImprint,
            serialNumber,
            genTime,
            accuracy,
            ordering,
            nonce,
            tsa,
            extensions,
        } = options

        this.version = version ?? 1
        this.policy = new ObjectIdentifier({ value: policy })
        this.messageImprint = messageImprint
        this.serialNumber = serialNumber
        this.genTime = genTime
        this.accuracy = accuracy
        this.ordering = ordering ?? false
        this.nonce = nonce
        this.tsa = tsa
        this.extensions = extensions
    }

    /**
     * Converts the TSTInfo to its ASN.1 representation.
     *
     * Creates a SEQUENCE containing all the timestamp info fields in the proper order
     * according to RFC 3161 specification.
     *
     * @returns ASN.1 structure representing the timestamp info
     *
     * @example
     * ```typescript
     * const asn1 = tstInfo.toAsn1()
     * const der = asn1.encode()
     * ```
     */
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [
            der.integer(this.version),
            this.policy.toAsn1(),
            this.messageImprint.toAsn1(),
            der.primitive(UniversalTag.Integer, this.serialNumber),
            der.generalizedTime(this.genTime),
        ]

        if (this.accuracy) {
            values.push(this.accuracy.toAsn1())
        }

        if (this.ordering !== false) {
            values.push(der.boolean(this.ordering))
        }

        if (this.nonce) {
            values.push(der.primitive(UniversalTag.Integer, this.nonce))
        }

        if (this.tsa) {
            // TSA is [0] EXPLICIT GeneralName
            values.push(this.tsa.toAsn1().explicit(0))
        }

        if (this.extensions && this.extensions.length > 0) {
            const extensionsArray = this.extensions.map((ext) => ext.toAsn1())
            // Extensions are [1] IMPLICIT
            values.push(implicitTag(der.sequence(extensionsArray), 1))
        }

        return der.sequence(values)
    }

    /**
     * Creates a TSTInfo from an ASN.1 structure.
     *
     * Parses the ASN.1 SEQUENCE and extracts all optional and required fields
     * according to RFC 3161 specification.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed TSTInfo object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     *
     * @example
     * ```typescript
     * const asn1 = derToAsn1(tstInfoBytes)
     * const tstInfo = TSTInfo.fromAsn1(asn1)
     * console.log(tstInfo.genTime)
     * console.log(tstInfo.messageImprint.hashAlgorithm)
     * ```
     */
    static fromAsn1(asn1: Asn1Node): TSTInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.children
        if (values.length < 5) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 5 elements',
            )
        }

        // Version
        if (!values[0]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for version',
            )
        }
        const version = der.readNumber(values[0])
        if (version !== 1) {
            throw new Asn1ParseError(`Unsupported TSTInfo version: ${version}`)
        }

        // Policy
        if (!values[1]?.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OBJECT IDENTIFIER for policy',
            )
        }
        const policy = der.readOid(values[1])

        // MessageImprint
        const messageImprint = MessageImprint.fromAsn1(values[2])

        // Serial Number
        if (!values[3]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for serialNumber',
            )
        }
        const serialNumber = values[3].bytes()

        // GenTime
        if (!values[4]?.is(UniversalTag.GeneralizedTime)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected GeneralizedTime for genTime',
            )
        }
        const genTime = der.readTime(values[4])

        // Parse optional fields
        let accuracy: Accuracy | undefined
        let ordering = false
        let nonce: Uint8Array<ArrayBuffer> | undefined
        let tsa: GeneralName | undefined
        let extensions: Extension[] | undefined

        for (let i = 5; i < values.length; i++) {
            const value = values[i]

            if (value.is(UniversalTag.Sequence)) {
                // Could be Accuracy
                accuracy = Accuracy.fromAsn1(value)
            } else if (value.is(UniversalTag.Boolean)) {
                ordering = der.readBoolean(value)
            } else if (value.is(UniversalTag.Integer)) {
                nonce = value.bytes()
            } else if (value?.constructed) {
                const tagNumber = value.tag

                if (tagNumber === 0) {
                    // [0] GeneralName (TSA)
                    if (value.children.length > 0) {
                        tsa = GeneralName.fromAsn1(value.children[0])
                    }
                } else if (tagNumber === 1) {
                    // [1] IMPLICIT Extensions
                    extensions = implicitSequenceOf(value).children.map((ext) =>
                        Extension.fromAsn1(ext),
                    )
                }
            }
        }

        return new TSTInfo({
            version,
            policy,
            messageImprint,
            serialNumber,
            genTime,
            accuracy,
            ordering,
            nonce,
            tsa,
            extensions,
        })
    }

    static fromDer(bytes: Uint8Array<ArrayBuffer>): TSTInfo {
        return TSTInfo.fromAsn1(derToAsn1(bytes))
    }
}
