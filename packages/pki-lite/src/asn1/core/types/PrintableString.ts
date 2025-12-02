/**
 * ASN.1 Printable String type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface PrintableStringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

export class PrintableString extends BaseBlock {
    static override NAME = 'PrintableString'

    private _stringValue: string = ''

    constructor(params: PrintableStringParams = {}) {
        super({
            tagNumber: TagNumber.PRINTABLE_STRING,
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

    override get valueBlock() {
        return {
            ...super.valueBlock,
            value: this._stringValue, // Return string value for compatibility
        }
    }

    override toString(): string {
        return `PrintableString : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { PrintableString as Asn1PrintableString }
