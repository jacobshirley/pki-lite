/**
 * ASN.1 Teletex String type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface TeletexStringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

/**
 * ValueBlock wrapper for TeletexString
 */
class TeletexStringValueBlock {
    private _parent: TeletexString

    constructor(parent: TeletexString) {
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

export class TeletexString extends BaseBlock {
    static override NAME = 'TeletexString'

    _stringValue: string = ''
    private _valueBlock: TeletexStringValueBlock

    constructor(params: TeletexStringParams = {}) {
        super({
            tagNumber: TagNumber.TELETEX_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        this._valueBlock = new TeletexStringValueBlock(this)

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

    override get valueBlock(): TeletexStringValueBlock {
        return this._valueBlock
    }

    override toString(): string {
        return `TeletexString : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { TeletexString as Asn1TeletexString }
