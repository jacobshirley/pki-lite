/**
 * ASN.1 IA5 String type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface IA5StringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

/**
 * ValueBlock wrapper for IA5String
 */
class IA5StringValueBlock {
    private _parent: IA5String

    constructor(parent: IA5String) {
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

export class IA5String extends BaseBlock {
    static override NAME = 'IA5String'

    _stringValue: string = ''
    private _valueBlock: IA5StringValueBlock

    constructor(params: IA5StringParams = {}) {
        super({
            tagNumber: TagNumber.IA5_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        this._valueBlock = new IA5StringValueBlock(this)

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

    override get valueBlock(): IA5StringValueBlock {
        return this._valueBlock
    }

    override toString(): string {
        return `IA5String : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { IA5String as Asn1IA5String }
