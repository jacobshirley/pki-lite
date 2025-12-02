/**
 * ASN.1 Bit String type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface BitStringParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    unusedBits?: number
}

export class BitString extends BaseBlock {
    static override NAME = 'BIT STRING'

    private _unusedBits: number = 0

    constructor(params: BitStringParams = {}) {
        super({
            tagNumber: TagNumber.BIT_STRING,
            tagClass: params.tagClass,
            isConstructed: false,
        })

        if (params.valueHex) {
            const bytes = new Uint8Array(params.valueHex)
            if (bytes.length > 0) {
                this._unusedBits = bytes[0]
                this._valueHex = bytes.slice(1)
            }
        }

        if (params.unusedBits !== undefined) {
            this._unusedBits = params.unusedBits
        }
    }

    get unusedBits(): number {
        return this._unusedBits
    }

    set unusedBits(value: number) {
        this._unusedBits = value
    }

    override get valueBlock() {
        return {
            ...super.valueBlock,
            unusedBits: this._unusedBits,
        }
    }

    override encodeContent(): Uint8Array {
        const result = new Uint8Array(this._valueHex.length + 1)
        result[0] = this._unusedBits
        result.set(this._valueHex, 1)
        return result
    }

    override toString(): string {
        return `BIT STRING : ${this._valueHex.length * 8 - this._unusedBits} bits`
    }
}

// Alias for backwards compatibility
export { BitString as Asn1BitString }
