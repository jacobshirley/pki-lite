/**
 * ASN.1 Constructed type (context-specific or tagged)
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { CONSTRUCTED_BIT, TagClass } from '../constants.js'

export interface ConstructedParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: BaseBlock[]
    idBlock?: { tagClass?: number; tagNumber?: number }
}

export class Constructed extends BaseBlock {
    static override NAME = 'Constructed'

    constructor(params: ConstructedParams = {}) {
        super({
            tagNumber: params.idBlock?.tagNumber ?? params.tagNumber ?? 0,
            tagClass:
                params.idBlock?.tagClass ??
                params.tagClass ??
                TagClass.CONTEXT_SPECIFIC,
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
        const tagClassStr =
            this.tagClass === TagClass.CONTEXT_SPECIFIC
                ? 'CONTEXT'
                : this.tagClass === TagClass.APPLICATION
                  ? 'APPLICATION'
                  : 'PRIVATE'
        return `[${tagClassStr} ${this.tagNumber}] (${this._value.length} items)`
    }
}

// Alias for backwards compatibility
export { Constructed as Asn1Constructed }
