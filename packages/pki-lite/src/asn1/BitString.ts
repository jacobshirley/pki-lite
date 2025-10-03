import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

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
     * Creates a new BitString instance.
     *
     * @param options Configuration object
     * @param options.value The value as string, bytes, BitString, or PKI object
     */
    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | BitString | PkiBase
    }) {
        super()
        const { value } = options

        if (value instanceof BitString) {
            this.bytes = value.bytes
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
    toAsn1(): Asn1BaseBlock {
        return new asn1js.BitString({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a BitString from an ASN.1 BIT STRING structure.
     *
     * @param asn1 The ASN.1 BIT STRING to parse
     * @returns A new BitString instance
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     */
    static fromAsn1(asn1: Asn1BaseBlock): BitString {
        if (!(asn1 instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex =
            asn1.valueBlock.valueHexView ||
            asn1.valueBlock.valueBeforeDecodeView

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 BIT STRING',
            )
        }

        return new BitString({ value: new Uint8Array(valueHex) })
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
