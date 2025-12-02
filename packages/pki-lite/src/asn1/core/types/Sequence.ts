/**
 * ASN.1 Sequence type (constructed)
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface SequenceParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: BaseBlock[]
}

export class Sequence extends BaseBlock {
    static override NAME = 'SEQUENCE'

    constructor(params: SequenceParams = {}) {
        super({
            tagNumber: TagNumber.SEQUENCE,
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
        return `SEQUENCE (${this._value.length} items)`
    }
}

// Alias for backwards compatibility
export { Sequence as Asn1Sequence }
