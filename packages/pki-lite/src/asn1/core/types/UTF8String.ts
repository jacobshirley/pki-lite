/**
 * ASN.1 UTF8 String type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface Utf8StringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

export class Utf8String extends BaseBlock {
    static override NAME = 'UTF8String'

    private _stringValue: string = ''

    constructor(params: Utf8StringParams = {}) {
        super({
            tagNumber: TagNumber.UTF8_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        if (params.value !== undefined) {
            this._stringValue = params.value
            this._valueHex = new TextEncoder().encode(params.value)
        } else if (params.valueHex) {
            this._stringValue = new TextDecoder().decode(
                new Uint8Array(params.valueHex),
            )
        }
    }

    get value(): string {
        return this._stringValue
    }

    set value(val: string) {
        this._stringValue = val
        this._valueHex = new TextEncoder().encode(val)
    }

    override getValue(): string {
        return this._stringValue
    }

    override toString(): string {
        return `UTF8String : ${this._stringValue}`
    }
}

// Aliases for backwards compatibility
export { Utf8String as Asn1UTF8String }
export { Utf8String as Asn1Utf8String }
