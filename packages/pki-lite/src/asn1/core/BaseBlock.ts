/**
 * ASN.1 BaseBlock - The foundation for all ASN.1 types
 *
 * This is a custom implementation to replace asn1js.
 */

import {
    CONSTRUCTED_BIT,
    LENGTH_LONG_FORM_BIT,
    LONG_FORM_TAG,
    TagClass,
    TagClassEncoded,
} from './constants.js'

/**
 * Convert tagClass (1-4) to encoded value (0x00, 0x40, 0x80, 0xC0)
 */
function tagClassToEncoded(tagClass: number): number {
    switch (tagClass) {
        case TagClass.UNIVERSAL:
            return TagClassEncoded.UNIVERSAL
        case TagClass.APPLICATION:
            return TagClassEncoded.APPLICATION
        case TagClass.CONTEXT_SPECIFIC:
            return TagClassEncoded.CONTEXT_SPECIFIC
        case TagClass.PRIVATE:
            return TagClassEncoded.PRIVATE
        default:
            return TagClassEncoded.UNIVERSAL
    }
}

/**
 * Convert encoded tag class (0x00, 0x40, 0x80, 0xC0) to tagClass (1-4)
 */
export function encodedToTagClass(encoded: number): number {
    switch (encoded & 0xc0) {
        case TagClassEncoded.APPLICATION:
            return TagClass.APPLICATION
        case TagClassEncoded.CONTEXT_SPECIFIC:
            return TagClass.CONTEXT_SPECIFIC
        case TagClassEncoded.PRIVATE:
            return TagClass.PRIVATE
        default:
            return TagClass.UNIVERSAL
    }
}

/**
 * Parameters for constructing ASN.1 blocks
 */
export interface BaseBlockParams {
    /** Tag number */
    tagNumber?: number
    /** Tag class */
    tagClass?: number
    /** Whether this is a constructed type */
    isConstructed?: boolean
    /** Binary value (for primitive types) */
    valueHex?: ArrayBuffer | Uint8Array
}

export interface BaseBlockJson {
    blockName: string
    tagNumber: number
    tagClass: number
    isConstructed: boolean
    valueHex: string
}

/**
 * Base class for all ASN.1 types
 */
export abstract class BaseBlock {
    static NAME = 'BaseBlock'

    /** Tag number */
    tagNumber: number

    /** Tag class */
    tagClass: number

    /** Whether this is a constructed type */
    isConstructed: boolean

    /** Binary value storage for primitive types */
    protected _valueHex: Uint8Array

    /** Nested values for constructed types */
    protected _value: BaseBlock[]

    /** Original bytes before decode (for round-trip) */
    protected _valueBeforeDecodeView: Uint8Array | null = null

    constructor(params: BaseBlockParams = {}) {
        this.tagNumber = params.tagNumber ?? 0
        this.tagClass = params.tagClass ?? TagClass.UNIVERSAL
        this.isConstructed = params.isConstructed ?? false
        this._value = []

        if (params.valueHex) {
            this._valueHex = new Uint8Array(params.valueHex)
        } else {
            this._valueHex = new Uint8Array(0)
        }
    }

    /**
     * Returns the block name for identification
     */
    static blockName(): string {
        return this.NAME
    }

    /**
     * ID block for compatibility with asn1js
     */
    get idBlock(): {
        tagClass: number
        tagNumber: number
        isConstructed: boolean
    } {
        return {
            tagClass: this.tagClass,
            tagNumber: this.tagNumber,
            isConstructed: this.isConstructed,
        }
    }

    /**
     * Length block for compatibility with asn1js
     */
    get lenBlock(): { length: number } {
        return {
            length: this._valueHex.length,
        }
    }

    /**
     * Get value hex as ArrayBuffer (for compatibility)
     */
    get valueHex(): ArrayBuffer {
        // Create a new ArrayBuffer to avoid SharedArrayBuffer issues
        const result = new ArrayBuffer(this._valueHex.byteLength)
        new Uint8Array(result).set(this._valueHex)
        return result
    }

    /**
     * Set value hex
     */
    set valueHex(value: ArrayBuffer) {
        this._valueHex = new Uint8Array(value)
    }

    /**
     * Get value hex view as Uint8Array
     */
    get valueHexView(): Uint8Array {
        return this._valueHex
    }

    /**
     * Get original bytes before decode
     */
    get valueBeforeDecodeView(): Uint8Array {
        return this._valueBeforeDecodeView ?? this._valueHex
    }

    /**
     * Nested value block for accessing internals (compatibility)
     */
    get valueBlock(): {
        value: any
        valueHex: ArrayBuffer
        valueHexView: Uint8Array
        valueBeforeDecodeView: Uint8Array
        valueDec: number
        isHexOnly: boolean
        unusedBits: number
        isConstructed: boolean
        toString(): string
    } {
        return {
            value: this._value,
            valueHex: this.valueHex,
            valueHexView: this._valueHex,
            valueBeforeDecodeView: this.valueBeforeDecodeView,
            valueDec: this.toNumber(),
            isHexOnly: true,
            unusedBits: 0,
            isConstructed: this.isConstructed,
            toString: () => this.toString(),
        }
    }

    /**
     * Converts the value to a number (for Integer-like types)
     */
    protected toNumber(): number {
        if (this._valueHex.length === 0) return 0

        // Handle signed integers (two's complement)
        const isNegative = (this._valueHex[0] & 0x80) !== 0
        let result = 0

        if (isNegative) {
            // Two's complement negative number
            for (const byte of this._valueHex) {
                result = (result << 8) | (byte ^ 0xff)
            }
            return -(result + 1)
        } else {
            for (const byte of this._valueHex) {
                result = (result << 8) | byte
            }
            return result
        }
    }

    /**
     * Encode the tag byte(s)
     */
    protected encodeTag(): Uint8Array {
        const encodedClass = tagClassToEncoded(this.tagClass)
        const tagByte =
            encodedClass |
            (this.isConstructed ? CONSTRUCTED_BIT : 0) |
            (this.tagNumber < 31 ? this.tagNumber : LONG_FORM_TAG)

        if (this.tagNumber < 31) {
            return new Uint8Array([tagByte])
        }

        // Long form tag encoding
        const tagBytes: number[] = [tagByte]
        let value = this.tagNumber
        const encodedParts: number[] = []

        while (value > 0) {
            encodedParts.unshift(value & 0x7f)
            value >>= 7
        }

        for (let i = 0; i < encodedParts.length; i++) {
            if (i < encodedParts.length - 1) {
                tagBytes.push(encodedParts[i] | 0x80)
            } else {
                tagBytes.push(encodedParts[i])
            }
        }

        return new Uint8Array(tagBytes)
    }

    /**
     * Encode the length
     */
    protected encodeLength(length: number): Uint8Array {
        if (length < 128) {
            return new Uint8Array([length])
        }

        // Long form length
        const lengthBytes: number[] = []
        let value = length

        while (value > 0) {
            lengthBytes.unshift(value & 0xff)
            value >>= 8
        }

        return new Uint8Array([
            LENGTH_LONG_FORM_BIT | lengthBytes.length,
            ...lengthBytes,
        ])
    }

    /**
     * Encode the content (override in subclasses)
     */
    protected encodeContent(): Uint8Array {
        if (this.isConstructed) {
            const parts: Uint8Array[] = []
            for (const item of this._value) {
                parts.push(new Uint8Array(item.toBER(false)))
            }
            const totalLength = parts.reduce((sum, p) => sum + p.length, 0)
            const result = new Uint8Array(totalLength)
            let offset = 0
            for (const part of parts) {
                result.set(part, offset)
                offset += part.length
            }
            return result
        }
        return this._valueHex
    }

    /**
     * Encode to BER/DER format
     */
    toBER(sizeOnly?: boolean): ArrayBuffer {
        const content = this.encodeContent()
        const tag = this.encodeTag()
        const length = this.encodeLength(content.length)

        if (sizeOnly) {
            return new ArrayBuffer(tag.length + length.length + content.length)
        }

        const result = new Uint8Array(
            tag.length + length.length + content.length,
        )
        result.set(tag, 0)
        result.set(length, tag.length)
        result.set(content, tag.length + length.length)

        return result.buffer.slice(
            result.byteOffset,
            result.byteOffset + result.byteLength,
        )
    }

    /**
     * Convert to JSON representation
     */
    toJSON(): BaseBlockJson {
        return {
            blockName: (this.constructor as typeof BaseBlock).NAME,
            tagNumber: this.tagNumber,
            tagClass: this.tagClass,
            isConstructed: this.isConstructed,
            valueHex: Array.from(this._valueHex)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join(''),
        }
    }

    /**
     * String representation
     */
    toString(): string {
        return `[${(this.constructor as typeof BaseBlock).NAME}]`
    }

    /**
     * Get nested value (for compatibility with asn1js)
     */
    getValue(): any {
        return this._valueHex
    }

    /**
     * Check if two blocks are equal (compare DER encodings)
     */
    isEqual(other: BaseBlock): boolean {
        const thisDer = new Uint8Array(this.toBER(false))
        const otherDer = new Uint8Array(other.toBER(false))

        if (thisDer.length !== otherDer.length) {
            return false
        }

        for (let i = 0; i < thisDer.length; i++) {
            if (thisDer[i] !== otherDer[i]) {
                return false
            }
        }

        return true
    }
}
