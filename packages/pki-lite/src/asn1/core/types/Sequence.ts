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

/**
 * ValueBlock wrapper that allows property assignment
 */
class SequenceValueBlock {
    private _parent: Sequence

    constructor(parent: Sequence) {
        this._parent = parent
    }

    get value(): BaseBlock[] {
        return this._parent._value
    }

    set value(val: BaseBlock[]) {
        this._parent._value = val
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
        return true
    }

    get unusedBits(): number {
        return 0
    }

    get isConstructed(): boolean {
        return true
    }

    toString(): string {
        return this._parent.toString()
    }
}

export class Sequence extends BaseBlock {
    static override NAME = 'SEQUENCE'
    private _valueBlock: SequenceValueBlock

    constructor(params: SequenceParams = {}) {
        super({
            tagNumber: TagNumber.SEQUENCE,
            tagClass: params.tagClass,
            isConstructed: true,
            valueHex: params.valueHex,
        })
        this._value = params.value ?? []
        this._valueBlock = new SequenceValueBlock(this)
    }

    get value(): BaseBlock[] {
        return this._value
    }

    set value(val: BaseBlock[]) {
        this._value = val
    }

    override get valueBlock(): SequenceValueBlock {
        return this._valueBlock
    }

    override toString(): string {
        return this.toStringTree()
    }

    /**
     * Generate a tree-like string representation
     */
    toStringTree(indent: string = ''): string {
        const lines: string[] = [`SEQUENCE :`]
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
export { Sequence as Asn1Sequence }
