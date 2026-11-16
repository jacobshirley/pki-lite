import { Asn1Node, der, PkiBase } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 BIT STRING value.
 *
 * A BIT STRING is used to represent sequences of bits. It's commonly used in
 * PKI for public keys, signatures, and bit flags. The string can contain any
 * number of bits, not necessarily a multiple of 8.
 *
 * @asn
 * ```asn
 * BIT STRING ::= <value>
 * ```
 *
 * @example
 * ```typescript
 * // Create from bytes
 * const bitString = new BitString({ value: new Uint8Array([0x04, 0x20, 0xAB, 0xCD]) })
 *
 * // Create from PKI object (e.g., public key)
 * const publicKeyBitString = new BitString({ value: subjectPublicKeyInfo })
 *
 * // Get hex representation
 * console.log(bitString.toHexString()) // "0420abcd"
 * ```
 */
export class BitString extends PkiBase<BitString> {
    /**
     * The bytes representing this bit string.
     */
    bytes: Uint8Array<ArrayBuffer>

    /**
     * Number of unused bits (0-7) at the end of the last byte.
     */
    unusedBits: number

    /**
     * Creates a new BitString instance.
     *
     * @param options Configuration object
     * @param options.value The value as string, bytes, BitString, or PKI object
     * @param options.unusedBits Unused bits at the end of the last byte (default 0)
     */
    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | BitString | PkiBase
        unusedBits?: number
    }) {
        super()
        const { value } = options
        this.unusedBits = options.unusedBits ?? 0

        if (value instanceof BitString) {
            this.bytes = value.bytes
            this.unusedBits = options.unusedBits ?? value.unusedBits
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else if (value instanceof PkiBase) {
            this.bytes = value.toDer()
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    /**
     * Converts this BitString to its ASN.1 representation.
     *
     * @returns The ASN.1 BIT STRING structure
     */
    toAsn1(): Asn1Node {
        return der.bitString(this.bytes, this.unusedBits)
    }

    /**
     * Creates a BitString from an ASN.1 BIT STRING structure.
     *
     * @param asn1 The ASN.1 BIT STRING to parse
     * @returns A new BitString instance
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     */
    static fromAsn1(asn1: Asn1Node): BitString {
        const { bytes, unusedBits } = der.readBitString(asn1)
        return new BitString({ value: bytes, unusedBits })
    }

    /**
     * Returns the string representation of this BitString.
     * Decodes the bytes as UTF-8 text.
     *
     * @returns The decoded string
     */
    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the BitString to a hexadecimal string representation.
     * Each byte is represented as two lowercase hex digits.
     *
     * @returns The hexadecimal string (e.g., "0420abcd")
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }
}
