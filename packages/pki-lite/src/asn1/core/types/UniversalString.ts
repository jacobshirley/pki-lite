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

export class UniversalString extends BaseBlock {
    static override NAME = 'UniversalString'

    private _stringValue: string = ''

    constructor(params: UniversalStringParams = {}) {
        super({
            tagNumber: TagNumber.UNIVERSAL_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
        })

        if (params.value !== undefined) {
            this._stringValue = params.value
            this._valueHex = this.encodeUtf32BE(params.value)
        } else if (params.valueHex) {
            this._stringValue = this.decodeUtf32BE(
                new Uint8Array(params.valueHex),
            )
        }
    }

    private encodeUtf32BE(str: string): Uint8Array {
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
        for (let i = 0; i < bytes.length; i += 4) {
            const code =
                (bytes[i] << 24) |
                (bytes[i + 1] << 16) |
                (bytes[i + 2] << 8) |
                bytes[i + 3]
            result += String.fromCodePoint(code)
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

    override toString(): string {
        return `UniversalString : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { UniversalString as Asn1UniversalString }
