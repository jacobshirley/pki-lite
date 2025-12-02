/**
 * ASN.1 Integer type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface IntegerParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: number | bigint
}

export class Integer extends BaseBlock {
    static override NAME = 'INTEGER'

    constructor(params: IntegerParams = {}) {
        super({
            tagNumber: TagNumber.INTEGER,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        if (params.value !== undefined) {
            this._valueHex = this.encodeInteger(params.value)
        }
    }

    private encodeInteger(value: number | bigint): Uint8Array {
        if (typeof value === 'bigint') {
            return this.encodeBigInt(value)
        }

        // Handle zero
        if (value === 0) {
            return new Uint8Array([0])
        }

        const bytes: number[] = []
        let num = Math.abs(value)

        // Convert to bytes
        while (num > 0) {
            bytes.unshift(num & 0xff)
            num = Math.floor(num / 256)
        }

        if (value >= 0) {
            // For positive numbers, add leading zero if high bit is set
            if (bytes[0] & 0x80) {
                bytes.unshift(0)
            }
        } else {
            // Two's complement for negative numbers
            let carry = 1
            for (let i = bytes.length - 1; i >= 0; i--) {
                const inverted = ~bytes[i] & 0xff
                bytes[i] = (inverted + carry) & 0xff
                carry = inverted + carry > 0xff ? 1 : 0
            }
            // Add sign extension if needed
            if ((bytes[0] & 0x80) === 0) {
                bytes.unshift(0xff)
            }
        }

        return new Uint8Array(bytes)
    }

    private encodeBigInt(value: bigint): Uint8Array {
        if (value === 0n) {
            return new Uint8Array([0])
        }

        const isNegative = value < 0n
        let absValue = isNegative ? -value : value
        const bytes: number[] = []

        while (absValue > 0n) {
            bytes.unshift(Number(absValue & 0xffn))
            absValue >>= 8n
        }

        if (isNegative) {
            // Two's complement
            let carry = 1
            for (let i = bytes.length - 1; i >= 0; i--) {
                const inverted = ~bytes[i] & 0xff
                bytes[i] = (inverted + carry) & 0xff
                carry = inverted + carry > 0xff ? 1 : 0
            }
            if ((bytes[0] & 0x80) === 0) {
                bytes.unshift(0xff)
            }
        } else if (bytes[0] & 0x80) {
            bytes.unshift(0)
        }

        return new Uint8Array(bytes)
    }

    override get valueBlock() {
        const dec = this.toDecimal()
        return {
            ...super.valueBlock,
            valueDec: typeof dec === 'bigint' ? Number(dec) : dec,
        }
    }

    /**
     * Get the integer value as a number (may lose precision for large values)
     */
    toDecimal(): number | bigint {
        if (this._valueHex.length === 0) return 0

        const isNegative = (this._valueHex[0] & 0x80) !== 0

        if (!isNegative) {
            if (this._valueHex.length <= 6) {
                let result = 0
                for (const byte of this._valueHex) {
                    result = result * 256 + byte
                }
                return result
            } else {
                let result = 0n
                for (const byte of this._valueHex) {
                    result = result * 256n + BigInt(byte)
                }
                return result
            }
        } else {
            // Two's complement decoding
            const bytes = new Uint8Array(this._valueHex)
            let carry = 1
            for (let i = bytes.length - 1; i >= 0; i--) {
                const inverted = ~bytes[i] & 0xff
                bytes[i] = (inverted + carry) & 0xff
                carry = inverted + carry > 0xff ? 1 : 0
            }

            if (bytes.length <= 6) {
                let result = 0
                for (const byte of bytes) {
                    result = result * 256 + byte
                }
                return -result
            } else {
                let result = 0n
                for (const byte of bytes) {
                    result = result * 256n + BigInt(byte)
                }
                return -result
            }
        }
    }

    override toString(): string {
        return `INTEGER : ${this.toDecimal()}`
    }
}

// Alias for backwards compatibility
export { Integer as Asn1Integer }
