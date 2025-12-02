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

export class IA5String extends BaseBlock {
    static override NAME = 'IA5String'

    private _stringValue: string = ''

    constructor(params: IA5StringParams = {}) {
        super({
            tagNumber: TagNumber.IA5_STRING,
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
        return `IA5String : ${this._stringValue}`
    }
}

// Alias for backwards compatibility
export { IA5String as Asn1IA5String }
