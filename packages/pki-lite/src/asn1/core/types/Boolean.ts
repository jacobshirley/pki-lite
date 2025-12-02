/**
 * ASN.1 Boolean type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface BooleanParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: boolean
}

// Note: We use "Boolean" as class name for asn1js compatibility
// even though it shadows the global Boolean
class BooleanClass extends BaseBlock {
    static override NAME = 'BOOLEAN'

    private _boolValue: boolean

    constructor(params: BooleanParams = {}) {
        super({
            tagNumber: TagNumber.BOOLEAN,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        if (params.value !== undefined) {
            this._boolValue = params.value
            this._valueHex = new Uint8Array([params.value ? 0xff : 0x00])
        } else if (params.valueHex) {
            const bytes = new Uint8Array(params.valueHex)
            this._boolValue = bytes.length > 0 && bytes[0] !== 0
        } else {
            this._boolValue = false
            this._valueHex = new Uint8Array([0x00])
        }
    }

    get value(): boolean {
        return this._boolValue
    }

    set value(val: boolean) {
        this._boolValue = val
        this._valueHex = new Uint8Array([val ? 0xff : 0x00])
    }

    override getValue(): boolean {
        return this._boolValue
    }

    override get valueBlock() {
        return {
            ...super.valueBlock,
            value: this._boolValue,
        }
    }

    override toString(): string {
        return `BOOLEAN: ${this._boolValue ? 'TRUE' : 'FALSE'}`
    }
}

// Export with name that matches asn1js
export { BooleanClass as Boolean }
// Alias for backwards compatibility
export { BooleanClass as Asn1Boolean }
