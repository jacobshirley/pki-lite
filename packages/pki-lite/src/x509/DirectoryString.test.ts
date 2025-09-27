import { describe, it, expect } from 'vitest'
import { DirectoryString } from './DirectoryString.js'
import { asn1js } from '../core/PkiBase.js'
import { TeletexString } from '../asn1/TeletexString.js'
import { PrintableString } from '../asn1/PrintableString.js'
import { UniversalString } from '../asn1/UniversalString.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { BMPString } from '../asn1/BMPString.js'

function makeAsn1String(Type: any, value: string) {
    const asn1 = new Type()
    asn1.valueBlock.value = value
    return asn1
}

describe('DirectoryString', () => {
    it('should parse TeletexString', () => {
        const asn1 = makeAsn1String(asn1js.TeletexString, 'abc')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(TeletexString)
        expect(result.toString()).toBe('abc')
    })

    it('should parse PrintableString', () => {
        const asn1 = makeAsn1String(asn1js.PrintableString, 'def')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(PrintableString)
        expect(result.toString()).toBe('def')
    })

    it('should parse UniversalString', () => {
        const asn1 = makeAsn1String(asn1js.UniversalString, 'ghi')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(UniversalString)
        expect(result.toString()).toBe('ghi')
    })

    it('should parse Utf8String', () => {
        const asn1 = makeAsn1String(asn1js.Utf8String, 'jkl')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(UTF8String)
        expect(result.toString()).toBe('jkl')
    })

    it('should parse BmpString', () => {
        const asn1 = makeAsn1String(asn1js.BmpString, 'mno')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(BMPString)
        expect(result.toString()).toBe('mno')
    })

    it('should throw on invalid ASN.1 type', () => {
        const fake = { __proto__: {}, valueBlock: { value: 'bad' } }
        expect(() => DirectoryString.fromAsn1(fake as any)).toThrow(
            'Invalid DirectoryString ASN.1 structure',
        )
    })

    it('should call toAsn1 on value', () => {
        const value = { toAsn1: () => 'asn1-value' } as any
        expect(DirectoryString.toAsn1(value)).toBe('asn1-value')
    })
})
