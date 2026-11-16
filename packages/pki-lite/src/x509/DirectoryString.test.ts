import { describe, it, expect } from 'vitest'
import { der } from '../core/PkiBase.js'
import { DirectoryString } from './DirectoryString.js'
import { TeletexString } from '../asn1/TeletexString.js'
import { PrintableString } from '../asn1/PrintableString.js'
import { UniversalString } from '../asn1/UniversalString.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { BMPString } from '../asn1/BMPString.js'

describe('DirectoryString', () => {
    it('should parse TeletexString', () => {
        const asn1 = der.teletexString('abc')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(TeletexString)
        expect(result.toString()).toEqual('abc')
    })

    it('should parse PrintableString', () => {
        const asn1 = der.printableString('def')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(PrintableString)
        expect(result.toString()).toEqual('def')
    })

    it('should parse UniversalString', () => {
        const asn1 = der.universalString('ghi')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(UniversalString)
        expect(result.toString()).toEqual('ghi')
    })

    it('should parse Utf8String', () => {
        const asn1 = der.utf8String('jkl')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(UTF8String)
        expect(result.toString()).toEqual('jkl')
    })

    it('should parse BmpString', () => {
        const asn1 = der.bmpString('mno')
        const result = DirectoryString.fromAsn1(asn1)
        expect(result).toBeInstanceOf(BMPString)
        expect(result.toString()).toEqual('mno')
    })

    it('should throw on invalid ASN.1 type', () => {
        expect(() => DirectoryString.fromAsn1(der.integer(1))).toThrow(
            'Invalid DirectoryString ASN.1 structure',
        )
    })

    it('should call toAsn1 on value', () => {
        const value = { toAsn1: () => 'asn1-value' } as any
        expect(DirectoryString.toAsn1(value)).toEqual('asn1-value')
    })
})
