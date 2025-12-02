/**
 * ASN.1 Object Identifier type
 */

import { BaseBlock, BaseBlockParams } from '../BaseBlock.js'
import { TagNumber } from '../constants.js'

export interface ObjectIdentifierParams {
    tagNumber?: number
    tagClass?: number
    isConstructed?: boolean
    valueHex?: ArrayBuffer | Uint8Array
    value?: string
}

export class ObjectIdentifier extends BaseBlock {
    static override NAME = 'OBJECT IDENTIFIER'

    private _oidValue: string = ''

    constructor(params: ObjectIdentifierParams = {}) {
        super({
            tagNumber: TagNumber.OBJECT_IDENTIFIER,
            tagClass: params.tagClass,
            isConstructed: false,
            valueHex: params.valueHex,
        })

        if (params.value) {
            this._oidValue = params.value
            this._valueHex = this.encodeOid(params.value)
        } else if (params.valueHex) {
            this._oidValue = this.decodeOid(new Uint8Array(params.valueHex))
        }
    }

    get value(): string {
        return this._oidValue
    }

    set value(val: string) {
        this._oidValue = val
        this._valueHex = this.encodeOid(val)
    }

    override getValue(): string {
        return this._oidValue
    }

    override get valueBlock() {
        return {
            ...super.valueBlock,
            toString: () => this._oidValue,
        }
    }

    private encodeOid(oid: string): Uint8Array {
        const parts = oid.split('.').map((s) => parseInt(s, 10))

        if (parts.length < 2) {
            throw new Error('Invalid OID: must have at least 2 components')
        }

        const bytes: number[] = []

        // First two components are combined: first * 40 + second
        const firstByte = parts[0] * 40 + parts[1]
        bytes.push(firstByte)

        // Remaining components use base-128 encoding
        for (let i = 2; i < parts.length; i++) {
            const component = parts[i]
            if (component < 128) {
                bytes.push(component)
            } else {
                const componentBytes: number[] = []
                let value = component
                componentBytes.unshift(value & 0x7f)
                value >>= 7
                while (value > 0) {
                    componentBytes.unshift((value & 0x7f) | 0x80)
                    value >>= 7
                }
                bytes.push(...componentBytes)
            }
        }

        return new Uint8Array(bytes)
    }

    private decodeOid(bytes: Uint8Array): string {
        if (bytes.length === 0) return ''

        const components: number[] = []

        // First byte encodes first two components
        const firstByte = bytes[0]
        components.push(Math.floor(firstByte / 40))
        components.push(firstByte % 40)

        // Decode remaining components
        let value = 0
        for (let i = 1; i < bytes.length; i++) {
            const byte = bytes[i]
            value = (value << 7) | (byte & 0x7f)
            if ((byte & 0x80) === 0) {
                components.push(value)
                value = 0
            }
        }

        return components.join('.')
    }

    override toString(): string {
        return `OBJECT IDENTIFIER : ${this._oidValue}`
    }
}

// Alias for backwards compatibility
export { ObjectIdentifier as Asn1ObjectIdentifier }
