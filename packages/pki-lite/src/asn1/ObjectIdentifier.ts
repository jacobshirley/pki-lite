import { OIDs } from '../core/OIDs.js'
import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    ObjectIdentifierString,
    PkiBase,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 OBJECT IDENTIFIER value.
 *
 * Object Identifiers (OIDs) are hierarchically structured identifiers used throughout
 * PKI and cryptographic standards to uniquely identify algorithms, attributes, and
 * other objects. They are represented as dot-separated sequences of integers.
 *
 * @asn
 * ```asn
 * OBJECT IDENTIFIER ::= <value>
 * ```
 *
 * @example
 * ```typescript
 * // Create an OID for RSA encryption
 * const rsaOid = new ObjectIdentifier({ value: '1.2.840.113549.1.1.1' })
 *
 * // Check if it matches a known OID
 * if (rsaOid.is('1.2.840.113549.1.1.1')) {
 *     console.log('RSA algorithm detected')
 * }
 *
 * // Get friendly name if available
 * console.log(rsaOid.friendlyName) // "rsaEncryption"
 * ```
 */
export class ObjectIdentifier extends PkiBase<ObjectIdentifier> {
    /**
     * The dot-separated OID value (e.g., "1.2.840.113549.1.1.1").
     */
    value: string

    /**
     * Creates a new ObjectIdentifier instance.
     *
     * @param options Configuration object
     * @param options.value The OID value as string, ObjectIdentifier, or object with toString()
     * @throws Error if value is null, undefined, or invalid
     */
    constructor(options: { value: ObjectIdentifierString | ObjectIdentifier }) {
        super()
        const { value } = options

        if (!value && value !== '') {
            throw new Error(
                'ObjectIdentifier value cannot be undefined or null',
            )
        }

        if (value instanceof ObjectIdentifier) {
            this.value = value.value
        } else if (typeof value === 'string') {
            this.value = value
        } else if (value && typeof value.toString === 'function') {
            this.value = value.toString()
        } else {
            throw new Error(
                'ObjectIdentifier value must be a string, ObjectIdentifier instance, or object with toString() method',
            )
        }
    }

    /**
     * Converts this ObjectIdentifier to its ASN.1 representation.
     *
     * @returns The ASN.1 OBJECT IDENTIFIER structure
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.ObjectIdentifier({ value: this.value })
    }

    /**
     * Creates an ObjectIdentifier from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 OBJECT IDENTIFIER to parse
     * @returns A new ObjectIdentifier instance
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     */
    static fromAsn1(asn1: Asn1BaseBlock): ObjectIdentifier {
        if (!(asn1 instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
            )
        }

        const oidValue = asn1.valueBlock.toString()
        if (!oidValue) {
            throw new Asn1ParseError(
                'Invalid ObjectIdentifier: no value found in ASN.1 structure',
            )
        }

        return new ObjectIdentifier({ value: oidValue })
    }

    /**
     * Creates an ObjectIdentifier from DER-encoded bytes.
     *
     * @param bytes The DER-encoded OBJECT IDENTIFIER bytes
     * @returns A new ObjectIdentifier instance
     */
    static fromDer(bytes: Uint8Array<ArrayBuffer>): ObjectIdentifier {
        return ObjectIdentifier.fromAsn1(derToAsn1(bytes))
    }

    /**
     * Returns the string representation of this OID.
     *
     * @returns The dot-separated OID value
     */
    toString() {
        return this.value
    }

    /**
     * Checks if this OID equals another OID.
     *
     * @param other The OID to compare with (ObjectIdentifier instance or string)
     * @returns true if the OIDs are equal, false otherwise
     */
    is(other: ObjectIdentifier | string): boolean {
        if (other instanceof ObjectIdentifier) {
            return this.value === other.value
        } else if (typeof other === 'string') {
            return this.value === other
        }
        return false
    }

    /**
     * Checks if this OID does not equal another OID.
     *
     * @param other The OID to compare with (ObjectIdentifier instance or string)
     * @returns true if the OIDs are different, false otherwise
     */
    isNot(other: ObjectIdentifier | string): boolean {
        return !this.is(other)
    }

    /**
     * Gets a human-readable name for this OID if available.
     * Falls back to the OID value if no friendly name is known.
     *
     * @returns A friendly name (e.g., "rsaEncryption") or the OID value
     */
    get friendlyName(): string {
        return OIDs.getOidFriendlyName(this.value) || this.value
    }
}
