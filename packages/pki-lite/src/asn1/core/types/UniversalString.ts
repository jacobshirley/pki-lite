/**
 * ASN.1 Universal String type (UTF-32BE encoding)
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface UniversalStringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

/**
 * ValueBlock wrapper for UniversalString
 */
class UniversalStringValueBlock {
    private _parent: UniversalString

    constructor(parent: UniversalString) {
        this._parent = parent
    }

    get value(): string {
        return this._parent._stringValue
    }

    set value(val: string) {
        this._parent._stringValue = val
        this._parent._valueHex = this._parent.encodeUtf32BE(val)
    }

    get valueHex(): ArrayBuffer {
        return this._parent.valueHex
    }

    get valueHexView(): Uint8Array {
        return this._parent.valueHexView
    }

    get valueBeforeDecodeView(): Uint8Array {
        return this._parent.valueBeforeDecodeView
    }

    get valueDec(): number {
        return 0
    }

    get isHexOnly(): boolean {
        return false
    }

    get unusedBits(): number {
        return 0
    }

    get isConstructed(): boolean {
        return false
    }

    toString(): string {
        return this._parent._stringValue
    }
}

export class UniversalString extends BaseBlock {
    static override NAME = 'UniversalString'

    _stringValue: string = ''
    private _valueBlock: UniversalStringValueBlock

    constructor(params: UniversalStringParams = {}) {
        super({
            tagNumber: TagNumber.UNIVERSAL_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
        })

        this._valueBlock = new UniversalStringValueBlock(this)

        if (params.value !== undefined) {
            this._stringValue = params.value
            this._valueHex = this.encodeUtf32BE(params.value)
        } else if (params.valueHex) {
            this._valueHex = new Uint8Array(params.valueHex)
            this._stringValue = this.decodeUtf32BE(this._valueHex)
        }
    }

    encodeUtf32BE(str: string): Uint8Array {
        const codePoints: number[] = []
        for (const char of str) {
            codePoints.push(char.codePointAt(0) ?? 0)
        }
        const bytes = new Uint8Array(codePoints.length * 4)
        for (let i = 0; i < codePoints.length; i++) {
            const code = codePoints[i]
            bytes[i * 4] = (code >> 24) & 0xff
            bytes[i * 4 + 1] = (code >> 16) & 0xff
            bytes[i * 4 + 2] = (code >> 8) & 0xff
            bytes[i * 4 + 3] = code & 0xff
        }
        return bytes
    }

    private decodeUtf32BE(bytes: Uint8Array): string {
        let result = ''
        for (let i = 0; i + 3 < bytes.length; i += 4) {
            // Use >>> 0 to ensure unsigned 32-bit integer
            const code =
                ((bytes[i] << 24) |
                    (bytes[i + 1] << 16) |
                    (bytes[i + 2] << 8) |
                    bytes[i + 3]) >>>
                0
            // Only decode valid code points
            if (code <= 0x10ffff) {
                result += String.fromCodePoint(code)
            }
        }
        return result
    }

    get value(): string {
        return this._stringValue
    }

    set value(val: string) {
        this._stringValue = val
        this._valueHex = this.encodeUtf32BE(val)
    }

    override getValue(): string {
        return this._stringValue
    }

    override get valueBlock(): UniversalStringValueBlock {
        return this._valueBlock
    }

    override toString(): string {
        return `UniversalString : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { UniversalString as Asn1UniversalString }
