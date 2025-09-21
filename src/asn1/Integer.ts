import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 INTEGER value.
 * Handles both small and large integers with full support for
 * multi-byte values including those exceeding JavaScript's Number limits.
 *
 * @asn
 * ```asn
 * Integer ::= <value>
 * ```
 */
export class Integer extends PkiBase<Integer> {
    bytes: Uint8Array

    /**
     * Creates a new Integer instance
     */
    constructor(options: {
        value: number | string | Uint8Array | Integer | bigint
    }) {
        super()
        const { value } = options

        if (value instanceof Integer) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else if (typeof value === 'bigint') {
            this.bytes = this.bigIntToBytes(value)
        } else if (typeof value === 'string') {
            try {
                // Try parsing as BigInt first for large numbers
                const bigIntValue = BigInt(value)
                this.bytes = this.bigIntToBytes(bigIntValue)
            } catch {
                // Fallback to Number if BigInt parsing fails
                const numberValue = Number(value)
                if (Number.isNaN(numberValue)) {
                    throw new Asn1ParseError('Invalid number string')
                }
                this.bytes = this.numberToBytes(numberValue)
            }
        } else {
            // Handle number type
            this.bytes = this.numberToBytes(value)
        }
    }

    /**
     * Converts a JavaScript Number to a Uint8Array in big-endian format
     */
    private numberToBytes(num: number): Uint8Array {
        // Handle small numbers efficiently
        if (num >= 0 && num < 128) {
            return new Uint8Array([num])
        }

        // For numbers >= 128, we need to handle ASN.1 encoding rules
        if (num >= 128 && num <= 255) {
            // In ASN.1, if the high bit is set, we need a leading 0 to indicate it's positive
            return new Uint8Array([0, num])
        }

        // For larger numbers, we need to properly encode them
        const bytes: number[] = []
        let tempNum = Math.abs(num)

        // Convert to bytes in little-endian first
        while (tempNum > 0) {
            bytes.unshift(tempNum & 0xff)
            tempNum = Math.floor(tempNum / 256)
        }

        // Handle negative numbers (two's complement)
        if (num < 0) {
            // Apply two's complement
            let carry = 1
            for (let i = bytes.length - 1; i >= 0; i--) {
                const inverted = ~bytes[i] & 0xff
                bytes[i] = (inverted + carry) & 0xff
                carry = inverted + carry > 0xff ? 1 : 0
            }

            // Add a sign byte if the highest bit is set
            if ((bytes[0] & 0x80) === 0) {
                bytes.unshift(0xff)
            }
        } else if (bytes.length > 0 && (bytes[0] & 0x80) !== 0) {
            // For positive numbers, add a leading zero if the high bit is set
            bytes.unshift(0x00)
        }

        return new Uint8Array(bytes.length === 0 ? [0] : bytes)
    }

    /**
     * Converts a BigInt to a Uint8Array in big-endian format
     */
    private bigIntToBytes(bigNum: bigint): Uint8Array {
        // Handle zero specially
        if (bigNum === 0n) {
            return new Uint8Array([0])
        }

        // Handle negative numbers (two's complement)
        const isNegative = bigNum < 0n
        let absValue = isNegative ? -bigNum : bigNum

        // Convert to byte array
        const bytes: number[] = []
        while (absValue > 0n) {
            bytes.unshift(Number(absValue & 0xffn))
            absValue = absValue >> 8n
        }

        // Ensure proper sign bit for ASN.1 encoding
        if (isNegative) {
            // Apply two's complement
            let carry = 1
            for (let i = bytes.length - 1; i >= 0; i--) {
                const inverted = ~bytes[i] & 0xff
                bytes[i] = (inverted + carry) & 0xff
                carry = inverted + carry > 0xff ? 1 : 0
            }

            // Add a sign byte if the highest bit is set (ASN.1 requirement)
            if ((bytes[0] & 0x80) === 0) {
                bytes.unshift(0xff) // Negative sign extension
            }
        } else if ((bytes[0] & 0x80) !== 0) {
            // For positive numbers, add a leading zero if the high bit is set
            // to prevent it from being interpreted as negative
            bytes.unshift(0x00)
        }

        return new Uint8Array(bytes)
    }

    /**
     * Converts the Integer to an ASN.1 INTEGER structure
     */
    toAsn1(): asn1js.Integer {
        // For ASN.1 encoding, check if we need to add padding for high bit values
        let valueHex = this.bytes

        // If the high bit is set (and this is a positive number),
        // we need to pad with a leading zero byte for ASN.1 DER encoding
        if ((this.bytes[0] & 0x80) !== 0) {
            // Add a leading zero byte to ensure it's interpreted as positive
            valueHex = new Uint8Array(this.bytes.length + 1)
            valueHex[0] = 0
            valueHex.set(this.bytes, 1)
        }

        return new asn1js.Integer({ valueHex })
    }

    /**
     * Creates an Integer from an ASN.1 INTEGER structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): Integer {
        if (!(asn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER',
            )
        }

        return new Integer({
            value: new Uint8Array(asn1.valueBlock.valueHexView),
        })
    }

    /**
     * Returns string representation of the integer
     */
    toString(): string {
        try {
            return this.toBigInt().toString()
        } catch {
            return this.toInteger().toString()
        }
    }

    /**
     * Converts to a JavaScript number.
     * Warning: Will lose precision for integers larger than Number.MAX_SAFE_INTEGER
     */
    toInteger(): number {
        // For empty array or single zero byte
        if (
            this.bytes.length === 0 ||
            (this.bytes.length === 1 && this.bytes[0] === 0)
        ) {
            return 0
        }

        // Check if this is a negative number (first bit is 1)
        const isNegative = (this.bytes[0] & 0x80) !== 0

        // For simple small positive values
        if (this.bytes.length === 1 && !isNegative) {
            return this.bytes[0]
        }

        // For negative numbers with a single byte
        if (this.bytes.length === 1 && isNegative) {
            // Convert from two's complement
            return -((~this.bytes[0] & 0xff) + 1)
        }

        // For larger values, use BigInt but warn about precision loss
        try {
            const bigValue = this.toBigInt()
            const numValue = Number(bigValue)

            // Check if conversion to Number lost precision
            if (
                bigValue > Number.MAX_SAFE_INTEGER ||
                bigValue < Number.MIN_SAFE_INTEGER
            ) {
                console.warn(
                    'Integer value exceeds safe JavaScript number range, precision may be lost',
                )
            }

            return numValue
        } catch (e) {
            return NaN
        }
    }

    /**
     * Alias of `toInteger()`
     * @returns The JavaScript number representation of the integer
     */
    toNumber(): number {
        return this.toInteger()
    }

    /**
     * Gets the integer value.
     * @returns The JavaScript number representation of the integer
     */
    get(): number {
        return this.toInteger()
    }

    /**
     * Converts to a BigInt value, which can handle integers of arbitrary precision
     */
    toBigInt(): bigint {
        if (this.bytes.length === 0) {
            return 0n
        }

        // Check if the number is negative (first bit is 1)
        const isNegative = (this.bytes[0] & 0x80) !== 0

        if (!isNegative) {
            // For positive numbers, simply convert from big-endian bytes to BigInt
            let result = 0n
            for (const byte of this.bytes) {
                result = (result << 8n) | BigInt(byte)
            }
            return result
        } else {
            // For negative numbers (in two's complement):
            // 1. Convert to positive by inverting and adding 1
            const complementBytes = new Uint8Array(this.bytes.length)
            let carry = 1

            for (let i = this.bytes.length - 1; i >= 0; i--) {
                const inverted = ~this.bytes[i] & 0xff
                complementBytes[i] = (inverted + carry) & 0xff
                carry = inverted + carry > 0xff ? 1 : 0
            }

            // 2. Convert to BigInt
            let result = 0n
            for (const byte of complementBytes) {
                result = (result << 8n) | BigInt(byte)
            }

            return -result // Apply the negative sign
        }
    }

    /**
     * Converts the Integer to a hexadecimal string
     * This method is primarily for display purposes and removes any leading zeros
     * added for ASN.1 encoding compliance
     */
    toHexString(): string {
        // For representation purposes, we'll strip any leading zeros for positive numbers
        // and represent the actual value compactly

        // Special case for zero
        if (
            this.bytes.length === 0 ||
            (this.bytes.length === 1 && this.bytes[0] === 0)
        ) {
            return '00'
        }

        // Check if this is a positive number with a leading 0 for ASN.1 encoding
        if (
            this.bytes.length >= 2 &&
            this.bytes[0] === 0 &&
            (this.bytes[1] & 0x80) !== 0
        ) {
            // Skip the leading zero for hex representation
            return Array.from(this.bytes.slice(1))
                .map((byte) => byte.toString(16).padStart(2, '0'))
                .join('')
        }

        // Otherwise, just convert all bytes
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }

    toUnsigned(): Uint8Array {
        // Strip leading 0x00 if present
        let result = this.bytes
        while (result.length > 1 && result[0] === 0x00) {
            result = result.slice(1)
        }
        return result
    }
}
