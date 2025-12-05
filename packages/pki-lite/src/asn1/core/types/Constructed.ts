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
    idBlock?: { tagClass?: number; tagNumber?: number; isConstructed?: boolean }
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
        return this.toStringTree()
    }

    /**
     * Generate a tree-like string representation
     */
    toStringTree(indent: string = ''): string {
        const lines: string[] = [`[${this.tagNumber}] :`]
        for (const child of this._value) {
            const childStr = this.childToString(child, indent + '  ')
            lines.push(`${indent}  ${childStr}`)
        }
        return lines.join('\n')
    }

    private childToString(child: BaseBlock, indent: string): string {
        if (
            'toStringTree' in child &&
            typeof child.toStringTree === 'function'
        ) {
            return (child as any).toStringTree(indent)
        }
        return child.toString()
    }
}

// Alias for backwards compatibility
export { Constructed as Asn1Constructed }
