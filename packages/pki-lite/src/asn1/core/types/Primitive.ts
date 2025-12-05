/**
 * ASN.1 Primitive type (generic primitive for unknown types)
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagClass } from '../constants.js'

export interface PrimitiveParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    idBlock?: { tagClass?: number; tagNumber?: number }
    lenBlock?: { length?: number }
}

export class Primitive extends BaseBlock {
    static override NAME = 'Primitive'

    constructor(params: PrimitiveParams = {}) {
        super({
            tagNumber: params.idBlock?.tagNumber ?? params.tagNumber ?? 0,
            tagClass:
                params.idBlock?.tagClass ??
                params.tagClass ??
                TagClass.CONTEXT_SPECIFIC,
            isConstructed: false,
            valueHex: params.valueHex,
        })
    }

    override toString(): string {
        const tagClassStr =
            this.tagClass === TagClass.CONTEXT_SPECIFIC
                ? 'CONTEXT'
                : this.tagClass === TagClass.APPLICATION
                  ? 'APPLICATION'
                  : this.tagClass === TagClass.UNIVERSAL
                    ? 'UNIVERSAL'
                    : 'PRIVATE'
        return `[${tagClassStr} ${this.tagNumber}] PRIMITIVE (${this._valueHex.length} bytes)`
    }
}

// Alias for backwards compatibility
export { Primitive as Asn1Primitive }
