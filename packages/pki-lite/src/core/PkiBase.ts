import * as asn1js from 'asn1js'
import { Any } from '../asn1/Any.js'
export * as asn1js from 'asn1js'
import { Asn1ParseError } from './errors/Asn1ParseError.js'

// Fixes an issue where asn1js.Boolean.toString would return
// `BOOLEAN : getValue() {
//        return this.valueBlock.value;
//  }`
asn1js.Boolean.prototype.toString = function () {
    return `BOOLEAN: ${('' + this.getValue()).toUpperCase()}`
}

export type Asn1BaseBlock = asn1js.BaseBlock

// TODO
export type ToJson<T> = {
    [K in keyof T]: T[K] extends object ? ToJson<T[K]> : T[K]
}

/**
 * Interface for types that can be parsed from ASN.1 or DER encoding.
 *
 * @template T The type that can be parsed
 */
export type ParseableAsn1<T> = {
    fromAsn1?(asn1: Asn1BaseBlock): T
    fromDer?(der: Uint8Array): T
}

/**
 * Base class for all PKI objects in the library.
 *
 * Provides common functionality for ASN.1 encoding/decoding, PEM formatting,
 * DER serialization, and object comparison. All PKI structures extend this class
 * to ensure consistent behavior across the library.
 *
 * @template T The specific PKI type that extends this base class
 */
export abstract class PkiBase<T extends object = any> {
    /**
     * Converts this PKI object to its ASN.1 representation.
     *
     * @returns The ASN.1 representation of this object
     */
    abstract toAsn1(): Asn1BaseBlock

    /**
     * Gets the PKI type name for this object (typically the class name).
     * Used for PEM headers and debugging output.
     */
    get pkiType(): string {
        return this.constructor.name
    }

    /**
     * Gets the PEM header name for this object type.
     * Converts the class name to uppercase for use in PEM encoding.
     */
    get pemHeader(): string {
        return this.pkiType.toUpperCase()
    }

    /**
     * Converts this object to a JSON representation.
     *
     * @returns A JSON-serializable representation of this object
     */
    toJSON(): ToJson<T> {
        return JSON.parse(JSON.stringify(this)) as T
    }

    /**
     * Returns a string representation of this PKI object.
     * Includes the type name and ASN.1 structure.
     *
     * @returns A string representation for debugging
     */
    toString(): string {
        return `[${this.pkiType}] ${this.toAsn1().toString()}`
    }

    /**
     * Returns a human-readable string representation of this object.
     * By default, returns the same as toString(), but subclasses can override
     * for more user-friendly output.
     *
     * @returns A human-readable string representation
     */
    toHumanString(): string {
        // By default, just return the same as toString
        return this.toString()
    }

    /**
     * Converts this PKI object to DER (Distinguished Encoding Rules) format.
     *
     * @returns The DER-encoded bytes of this object
     */
    toDer(): Uint8Array<ArrayBuffer> {
        return asn1ToDer(this.toAsn1())
    }

    /**
     * Converts this PKI object to PEM (Privacy-Enhanced Mail) format.
     *
     * @returns A PEM-encoded string with appropriate headers
     */
    toPem(): string {
        const der = this.toDer()
        const base64 = arrayToBase64(der)
        return `-----BEGIN ${this.pemHeader}-----\n${base64}\n-----END ${this.pemHeader}-----`
    }

    /**
     * Compares this PKI object with another for equality.
     * Two objects are considered equal if their DER encodings are identical.
     *
     * @param other The other PKI object to compare with
     * @returns true if the objects are equal, false otherwise
     */
    equals(other: PkiBase<any>): boolean {
        return this.toDer().toString() === other.toDer().toString()
    }

    /**
     * Parses this object as a different PKI type.
     * Useful for converting between related PKI structures.
     *
     * @template T The target type to parse as
     * @param type The target type constructor with parsing capabilities
     * @returns A new instance of the target type
     */
    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.toDer())
        } else if (type.fromAsn1) {
            return type.fromAsn1(this.toAsn1())
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }
}

/**
 * Base class for arrays of PKI objects.
 *
 * Extends the native Array class with PKI-specific functionality including
 * size limits, PEM encoding, and ASN.1 serialization capabilities.
 *
 * @template T The type of PKI objects contained in this array
 */
export abstract class PkiArray<T extends PkiBase<any>> extends Array<T> {
    protected maxSize?: number

    /**
     * Adds new PKI objects to the end of the array.
     * Respects the maxSize limit if set.
     *
     * @param items The PKI objects to add
     * @returns The new length of the array
     * @throws Error if adding items would exceed maxSize
     */
    push(...items: T[]): number {
        if (!this.maxSize) {
            return super.push(...items)
        }

        let newLen = this.length + items.length
        if (newLen > this.maxSize) {
            throw new Error(`Max size exceeded: ${this.maxSize}`)
        }
        return super.push(...items)
    }

    /**
     * Gets the PKI type name for this array.
     */
    get pkiType(): string {
        return this.constructor.name
    }

    /**
     * Gets the PEM header name for this array type.
     */
    get pemHeader(): string {
        return this.pkiType.toUpperCase()
    }

    /**
     * Converts this array to a JSON representation.
     *
     * @returns A JSON-serializable representation of this array
     */
    toJSON(): ToJson<T> {
        return JSON.parse(JSON.stringify(this)) as T
    }

    /**
     * Returns a string representation of this PKI array.
     *
     * @returns A string representation for debugging
     */
    toString(): string {
        return `[${this.pkiType}] ${this.toAsn1().toString()}`
    }

    /**
     * Converts this array to DER format.
     *
     * @returns The DER-encoded bytes of this array
     */
    toDer(): Uint8Array<ArrayBuffer> {
        return asn1ToDer(this.toAsn1())
    }

    /**
     * Converts this array to PEM format.
     *
     * @returns A PEM-encoded string
     */
    toPem(): string {
        const der = this.toDer()
        const base64 = arrayToBase64(der)
        return `-----BEGIN ${this.pemHeader}-----\n${base64}\n-----END ${this.pemHeader}-----`
    }

    /**
     * Converts this array to its ASN.1 representation.
     * Must be implemented by subclasses to specify SET or SEQUENCE.
     *
     * @returns The ASN.1 representation of this array
     */
    abstract toAsn1(): Asn1BaseBlock
}

/**
 * Represents a SET OF PKI objects in ASN.1.
 *
 * A SET contains an unordered collection of objects of the same type.
 * This class provides SET-specific ASN.1 encoding and comparison methods.
 *
 * @template T The type of PKI objects contained in this set
 */
export class PkiSet<T extends PkiBase<any> = any> extends PkiArray<T> {
    /**
     * Converts this set to ASN.1 SET structure.
     *
     * @returns An ASN.1 SET containing all items in this collection
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Set({
            value: [...this].map((item) => item.toAsn1()),
        })
    }

    /**
     * Compares this set with another for equality.
     * Two sets are considered equal if they have the same length and
     * all corresponding items are equal.
     *
     * @param other The other set to compare with
     * @returns true if the sets are equal, false otherwise
     */
    equals(other: PkiSet<T>): boolean {
        if (this.length !== other.length) {
            return false
        }

        for (let i = 0; i < this.length; i++) {
            if (!this[i].equals(other[i])) {
                return false
            }
        }

        return true
    }

    /**
     * Parses this set as a different PKI type.
     *
     * @template T The target type to parse as
     * @param type The target type constructor with parsing capabilities
     * @returns A new instance of the target type
     */
    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.toDer())
        } else if (type.fromAsn1) {
            return type.fromAsn1(this.toAsn1())
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }

    /**
     * Returns a human-readable string representation of this set.
     * Joins all child elements with commas.
     *
     * @returns A comma-separated string of child elements
     */
    toHumanString(): string {
        return this.map((child) => child.toHumanString()).join(', ')
    }
}

/**
 * Represents a SEQUENCE OF PKI objects in ASN.1.
 *
 * A SEQUENCE contains an ordered collection of objects, which may be of
 * different types. This class provides SEQUENCE-specific ASN.1 encoding
 * and comparison methods.
 *
 * @template T The type of PKI objects contained in this sequence
 */
export class PkiSequence<T extends PkiBase<any> = any> extends PkiArray<T> {
    /**
     * Converts this sequence to ASN.1 SEQUENCE structure.
     *
     * @returns An ASN.1 SEQUENCE containing all items in order
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [...this].map((item) => item.toAsn1()),
        })
    }

    /**
     * Compares this sequence with another for equality.
     * Two sequences are considered equal if they have the same length and
     * all corresponding items are equal in the same order.
     *
     * @param other The other sequence to compare with
     * @returns true if the sequences are equal, false otherwise
     */
    equals(other: PkiSequence<T>): boolean {
        if (this.length !== other.length) {
            return false
        }

        for (let i = 0; i < this.length; i++) {
            if (!this[i].equals(other[i])) {
                return false
            }
        }

        return true
    }

    /**
     * Parses this sequence as a different PKI type.
     *
     * @template T The target type to parse as
     * @param type The target type constructor with parsing capabilities
     * @returns A new instance of the target type
     */
    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.toDer())
        } else if (type.fromAsn1) {
            return type.fromAsn1(this.toAsn1())
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }

    /**
     * Returns a human-readable string representation of this sequence.
     * Joins all child elements with commas.
     *
     * @returns A comma-separated string of child elements
     */
    toHumanString(): string {
        return this.map((child) => child.toHumanString()).join(', ')
    }
}

/**
 * Converts an ASN.1 structure to DER (Distinguished Encoding Rules) format.
 *
 * @param value The ASN.1 structure to encode
 * @returns The DER-encoded bytes
 */
export function asn1ToDer(value: Asn1BaseBlock): Uint8Array<ArrayBuffer> {
    return new Uint8Array(value.toBER(false))
}

/**
 * Parses DER-encoded bytes into an ASN.1 structure.
 *
 * @param der The DER-encoded bytes to parse
 * @returns The parsed ASN.1 structure
 */
export function derToAsn1(der: Uint8Array | ArrayBuffer): Asn1BaseBlock {
    return asn1js.fromBER(der).result
}

/**
 * Converts a Uint8Array to a base64 string in a browser-compatible way.
 * Uses the btoa() function available in both browsers and Node.js.
 *
 * @param bytes The bytes to encode
 * @returns The base64-encoded string
 */
export function arrayToBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode.apply(null, Array.from(bytes)))
}

/**
 * Converts a base64 string to a Uint8Array in a browser-compatible way.
 * Uses the atob() function available in both browsers and Node.js.
 *
 * @param base64 The base64 string to decode
 * @returns The decoded bytes
 */
export function base64ToArray(base64: string): Uint8Array {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }
    return bytes
}

const hexChars = '0123456789ABCDEF'

/**
 * Converts bytes to hexadecimal byte representation.
 * Each input byte becomes two output bytes representing the hex digits.
 *
 * @param bytes The bytes to convert
 * @returns Hex representation as bytes (each hex digit as a byte)
 */
export function bytesToHexBytes(bytes: Uint8Array): Uint8Array {
    const result = new Uint8Array(bytes.length * 2)

    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]
        result[i * 2] = hexChars.charCodeAt((byte >> 4) & 0x0f)
        result[i * 2 + 1] = hexChars.charCodeAt(byte & 0x0f)
    }

    return result
}

/**
 * Converts bytes to a hexadecimal string representation.
 *
 * @param bytes The bytes to convert
 * @returns Uppercase hexadecimal string (e.g., "DEADBEEF")
 */
export function bytesToHexString(bytes: Uint8Array): string {
    let hex = ''
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]
        hex += hexChars.charAt((byte >> 4) & 0x0f)
        hex += hexChars.charAt(byte & 0x0f)
    }
    return hex
}

/**
 * Converts hexadecimal bytes back to regular bytes.
 * Expects input where each pair of bytes represents one hex digit pair.
 *
 * @param hex The hex bytes to convert (each pair of bytes = one output byte)
 * @returns The decoded bytes
 */
export function hexBytesToBytes(hex: Uint8Array): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(String.fromCharCode(hex[i], hex[i + 1]), 16)
    }
    return bytes
}

/**
 * Extracts DER-encoded data from a PEM-formatted string.
 * Supports multiple possible PEM header names for flexibility.
 *
 * @param pem The PEM-formatted string
 * @param name The PEM header name(s) to look for (e.g., "CERTIFICATE")
 * @returns The DER-encoded bytes
 * @throws Error if multiple PEM blocks are found or format is invalid
 */
export function pemToDer(pem: string, name: string | string[]): Uint8Array {
    const names = Array.isArray(name) ? name : [name]

    for (const n of names) {
        const regex = new RegExp(
            `-----BEGIN ${n}-----([\\s\\S]+?)-----END ${n}-----`,
            'g',
        )
        const matches = [...pem.matchAll(regex)]
        if (matches.length > 1) {
            throw new Error('Multiple PEM blocks found; expected only one')
        }

        if (matches.length === 1) {
            const b64 = matches[0][1].replace(/\s+/g, '')
            return base64ToArray(b64)
        }
    }

    throw new Asn1ParseError('Invalid PEM format')
}

/**
 * Creates a choice type for ASN.1 CHOICE constructs.
 * This is a helper function for creating discriminated union types.
 *
 * @template T The choice type
 * @param name The name of the choice for debugging
 * @param choices The possible choice values
 * @returns The choice object with a custom toString tag
 */
export function Choice<T>(name: string, choices: T): T {
    return {
        [Symbol.toStringTag]: name,
        ...choices,
    }
}

/**
 * Represents an object identifier (OID) that can be a string or object with toString().
 * OIDs are dot-separated numeric identifiers used throughout PKI standards.
 */
export type ObjectIdentifierString = string | { toString(): string }

/**
 * Union type for any value that can be converted to ASN.1.
 * Covers all the basic types that the library can work with.
 */
export type Asn1Any =
    | Uint8Array
    | Asn1BaseBlock
    | null
    | string
    | Any
    | PkiBase
    | number
    | boolean
