/**
 * ASN.1 Set type (constructed)
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface SetParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: BaseBlock[]
}

export class Set extends BaseBlock {
    static override NAME = 'SET'

    constructor(params: SetParams = {}) {
        super({
            tagNumber: TagNumber.SET,
            tagClass: params.tagClass,
            isConstructed: true,
            valueHex: params.valueHex,
        })
        this._value = params.value ?? []
    }

    get value(): BaseBlock[] {
        return this._value
    }

    set value(val: BaseBlock[]) {
        this._value = val
    }

    override get valueBlock() {
        return {
            ...super.valueBlock,
            value: this._value,
        }
    }

    override toString(): string {
        return `SET (${this._value.length} items)`
    }
}

// Alias for backwards compatibility
export { Set as Asn1Set }
