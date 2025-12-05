/**
 * ASN.1 BMP String type (Basic Multilingual Plane - UTF-16BE encoding)
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface BmpStringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

/**
 * ValueBlock wrapper for BmpString
 */
class BmpStringValueBlock {
    private _parent: BmpString

    constructor(parent: BmpString) {
        this._parent = parent
    }

    get value(): string {
        return this._parent._stringValue
    }

    set value(val: string) {
        this._parent._stringValue = val
        this._parent._valueHex = this._parent.encodeUtf16BE(val)
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

export class BmpString extends BaseBlock {
    static override NAME = 'BMPString'

    _stringValue: string = ''
    private _valueBlock: BmpStringValueBlock

    constructor(params: BmpStringParams = {}) {
        super({
            tagNumber: TagNumber.BMP_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
        })

        this._valueBlock = new BmpStringValueBlock(this)

        if (params.value !== undefined) {
            this._stringValue = params.value
            this._valueHex = this.encodeUtf16BE(params.value)
        } else if (params.valueHex) {
            this._valueHex = new Uint8Array(params.valueHex)
            this._stringValue = this.decodeUtf16BE(this._valueHex)
        }
    }

    encodeUtf16BE(str: string): Uint8Array {
        const bytes = new Uint8Array(str.length * 2)
        for (let i = 0; i < str.length; i++) {
            const code = str.charCodeAt(i)
            bytes[i * 2] = (code >> 8) & 0xff
            bytes[i * 2 + 1] = code & 0xff
        }
        return bytes
    }

    private decodeUtf16BE(bytes: Uint8Array): string {
        let result = ''
        for (let i = 0; i + 1 < bytes.length; i += 2) {
            const code = (bytes[i] << 8) | bytes[i + 1]
            result += String.fromCharCode(code)
        }
        return result
    }

    get value(): string {
        return this._stringValue
    }

    set value(val: string) {
        this._stringValue = val
        this._valueHex = this.encodeUtf16BE(val)
    }

    override getValue(): string {
        return this._stringValue
    }

    override get valueBlock(): BmpStringValueBlock {
        return this._valueBlock
    }

    override toString(): string {
        return `BMPString : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { BmpString as Asn1BmpString }
