import { describe, it, expect } from 'vitest'
import { PkiBase, PkiSet, Asn1BaseBlock, asn1js } from './PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'
import { Asn1ParseError } from './errors/Asn1ParseError.js'

class TestPkiItem extends PkiBase<TestPkiItem> {
    value: string

    constructor(value = '') {
        super()
        this.value = value
    }

    toAsn1(): Asn1BaseBlock {
        return new OctetString({ bytes: this.value }).toAsn1()
    }

    static fromAsn1(asn1: Asn1BaseBlock): TestPkiItem {
        if (asn1 instanceof asn1js.OctetString) {
            return new TestPkiItem(asn1.getValue().toString())
        }
        throw new Asn1ParseError('Invalid ASN.1 structure')
    }

    //@ts-expect-error
    toJSON() {
        return {
            value: this.value,
        }
    }
}

describe('PkiBase', () => {
    it('should handle JSON serialization', () => {
        const item = new TestPkiItem('test')
        const json = item.toJSON()
        expect(json).toEqual({ value: 'test' })
    })
})

describe('PkiSet', () => {
    it('should act like a set', () => {
        const item1 = new TestPkiItem('one')
        const item2 = new TestPkiItem('two')
        const set = new PkiSet(item1, item2, item1)
        expect(set.length).toBe(3) // PkiSet does not enforce uniqueness on construction
        expect(set.some((i) => i.value === item1.value)).toBe(true)
        expect(set.some((i) => i.value === item2.value)).toBe(true)
    })
})
