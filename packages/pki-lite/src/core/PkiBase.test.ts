import { describe, it, expect } from 'vitest'
import { PkiBase, PkiSet, Asn1BaseBlock, asn1js, derToAsn1 } from './PkiBase.js'
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
        expect(set.length).toEqual(3) // PkiSet does not enforce uniqueness on construction
        expect(set.some((i) => i.value === item1.value)).toEqual(true)
        expect(set.some((i) => i.value === item2.value)).toEqual(true)
    })
})

describe('toJSON', () => {
    it('serialises objects that do not override it (it used to recurse forever)', () => {
        const octets = new OctetString({ bytes: new Uint8Array([1, 2]) })
        expect(octets.toJSON()).toEqual({ bytes: { 0: 1, 1: 2 } })
        expect(() => JSON.stringify(octets)).not.toThrow()
    })

    it('serialises arrays of PKI objects', () => {
        const set = new PkiSet(new OctetString({ bytes: new Uint8Array([7]) }))
        expect(set.toJSON()).toEqual([{ bytes: { 0: 7 } }])
        expect(JSON.parse(JSON.stringify(set))).toEqual([{ bytes: { 0: 7 } }])
    })
})

describe('derToAsn1', () => {
    it('parses structures with more than 10,000 nodes (a CRL with thousands of entries)', () => {
        // SEQUENCE of 20,000 INTEGER 1 (02 01 01), over asn1js' default node limit
        const count = 20_000
        const body = new Uint8Array(count * 3)
        for (let i = 0; i < count; i++) body.set([0x02, 0x01, 0x01], i * 3)
        const der = new Uint8Array([0x30, 0x83, 0x00, 0xea, 0x60, ...body])
        const parsed = derToAsn1(der) as asn1js.Sequence
        expect(parsed.valueBlock.value).toHaveLength(count)
    })
})
