import { describe, it, expect } from 'vitest'
import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    PkiSequence,
    PkiSet,
} from './PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'
import { Asn1ParseError } from './errors/Asn1ParseError.js'

class TestPkiItem extends PkiBase<TestPkiItem> {
    value: string

    constructor(value = '') {
        super()
        this.value = value
    }

    toAsn1(): Asn1Node {
        return new OctetString({ bytes: this.value }).toAsn1()
    }

    static fromAsn1(asn1: Asn1Node): TestPkiItem {
        return new TestPkiItem(
            new TextDecoder().decode(der.readOctetString(asn1)),
        )
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

    it('round-trips through DER and parseAs', () => {
        const item = new TestPkiItem('test')
        expect(item.toDer()).toEqual(
            new Uint8Array([0x04, 0x04, 0x74, 0x65, 0x73, 0x74]),
        )
        expect(item.parseAs(TestPkiItem).value).toBe('test')
        expect(item.equals(new TestPkiItem('test'))).toBe(true)
        expect(item.equals(new TestPkiItem('other'))).toBe(false)
    })

    it('includes the type and ASN.1 dump in toString', () => {
        expect(new TestPkiItem('a').toString()).toBe(
            '[TestPkiItem] OCTET STRING : 61',
        )
    })
})

describe('derToAsn1', () => {
    it('throws on malformed input', () => {
        expect(() => derToAsn1(new Uint8Array([0x30, 0x05]))).toThrow(
            Asn1ParseError,
        )
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

    it('encodes as a SET in the given order', () => {
        const set = new PkiSet(new TestPkiItem('b'), new TestPkiItem('a'))
        expect(set.toDer()).toEqual(
            new Uint8Array([0x31, 0x06, 0x04, 0x01, 0x62, 0x04, 0x01, 0x61]),
        )
    })
})

describe('PkiSequence', () => {
    it('encodes as a SEQUENCE', () => {
        const seq = new PkiSequence(new TestPkiItem('a'))
        expect(seq.toDer()).toEqual(
            new Uint8Array([0x30, 0x03, 0x04, 0x01, 0x61]),
        )
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
