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

/**
 * ValueBlock wrapper for UTF8String
 */
class UTF8StringValueBlock {
    private _parent: Utf8String

    constructor(parent: Utf8String) {
        this._parent = parent
    }

    get value(): string {
        return this._parent._stringValue
    }

    set value(val: string) {
        this._parent._stringValue = val
        this._parent._valueHex = new TextEncoder().encode(val)
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

export class Utf8String extends BaseBlock {
    static override NAME = 'UTF8String'

    _stringValue: string = ''
    private _valueBlock: UTF8StringValueBlock

    constructor(params: Utf8StringParams = {}) {
        super({
            tagNumber: TagNumber.UTF8_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        this._valueBlock = new UTF8StringValueBlock(this)

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

    override get valueBlock(): UTF8StringValueBlock {
        return this._valueBlock
    }

    override toString(): string {
        return `UTF8String : '${this._stringValue}'`
    }
}

// Aliases for backwards compatibility
export { Utf8String as Asn1UTF8String }
export { Utf8String as Asn1Utf8String }
