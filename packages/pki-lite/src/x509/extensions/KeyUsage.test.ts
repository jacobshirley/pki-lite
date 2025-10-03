import { describe, it, expect } from 'vitest'
import { KeyUsage } from './KeyUsage.js'

describe('KeyUsage', () => {
    it('should create a KeyUsage with correct properties', () => {
        const usage = new KeyUsage({
            digitalSignature: true,
            keyEncipherment: true,
            keyAgreement: false,
        })
        expect(usage.digitalSignature).toEqual(true)
        expect(usage.keyEncipherment).toEqual(true)
        expect(usage.keyAgreement).toEqual(false)
        expect(usage.dataEncipherment).toEqual(false)
        expect(usage.keyCertSign).toEqual(false)
        expect(usage.cRLSign).toEqual(false)
        expect(usage.encipherOnly).toEqual(false)
        expect(usage.decipherOnly).toEqual(false)
        expect(usage.nonRepudiation).toEqual(false)
    })

    it('should encode and decode ASN.1 correctly', () => {
        const original = new KeyUsage({
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,
            keyAgreement: true,
            keyCertSign: true,
            cRLSign: true,
        })
        const asn1 = original.toAsn1()
        const decoded = KeyUsage.fromAsn1(asn1)
        expect(decoded.digitalSignature).toEqual(true)
        expect(decoded.nonRepudiation).toEqual(true)
        expect(decoded.keyEncipherment).toEqual(true)
        expect(decoded.dataEncipherment).toEqual(true)
        expect(decoded.keyAgreement).toEqual(true)
        expect(decoded.keyCertSign).toEqual(true)
        expect(decoded.cRLSign).toEqual(true)
        expect(decoded.encipherOnly).toEqual(false)
        expect(decoded.decipherOnly).toEqual(false)
    })

    it('should encode and decode all flags set', () => {
        const allTrue = new KeyUsage({
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,
            keyAgreement: true,
            keyCertSign: true,
            cRLSign: true,
            encipherOnly: true,
            decipherOnly: true,
        })
        const asn1 = allTrue.toAsn1()
        const decoded = KeyUsage.fromAsn1(asn1)
        expect(decoded.digitalSignature).toEqual(true)
        expect(decoded.nonRepudiation).toEqual(true)
        expect(decoded.keyEncipherment).toEqual(true)
        expect(decoded.dataEncipherment).toEqual(true)
        expect(decoded.keyAgreement).toEqual(true)
        expect(decoded.keyCertSign).toEqual(true)
        expect(decoded.cRLSign).toEqual(true)
        expect(decoded.encipherOnly).toEqual(true)
        expect(decoded.decipherOnly).toEqual(true)
    })

    it('should encode and decode all flags false', () => {
        const allFalse = new KeyUsage({})
        const asn1 = allFalse.toAsn1()
        const decoded = KeyUsage.fromAsn1(asn1)
        expect(decoded.digitalSignature).toEqual(false)
        expect(decoded.nonRepudiation).toEqual(false)
        expect(decoded.keyEncipherment).toEqual(false)
        expect(decoded.dataEncipherment).toEqual(false)
        expect(decoded.keyAgreement).toEqual(false)
        expect(decoded.keyCertSign).toEqual(false)
        expect(decoded.cRLSign).toEqual(false)
        expect(decoded.encipherOnly).toEqual(false)
        expect(decoded.decipherOnly).toEqual(false)
    })

    it('should throw if ASN.1 is not a BitString', () => {
        expect(() => KeyUsage.fromAsn1({} as any)).toThrow(
            `Expected BitString for KeyUsage`,
        )
    })
})
