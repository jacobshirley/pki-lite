import { describe, it, expect } from 'vitest'
import { KeyUsage } from './KeyUsage.js'

describe('KeyUsage', () => {
    it('should create a KeyUsage with correct properties', () => {
        const usage = new KeyUsage({
            digitalSignature: true,
            keyEncipherment: true,
            keyAgreement: false,
        })
        expect(usage.digitalSignature).toBe(true)
        expect(usage.keyEncipherment).toBe(true)
        expect(usage.keyAgreement).toBe(false)
        expect(usage.dataEncipherment).toBe(false)
        expect(usage.keyCertSign).toBe(false)
        expect(usage.cRLSign).toBe(false)
        expect(usage.encipherOnly).toBe(false)
        expect(usage.decipherOnly).toBe(false)
        expect(usage.nonRepudiation).toBe(false)
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
        expect(decoded.digitalSignature).toBe(true)
        expect(decoded.nonRepudiation).toBe(true)
        expect(decoded.keyEncipherment).toBe(true)
        expect(decoded.dataEncipherment).toBe(true)
        expect(decoded.keyAgreement).toBe(true)
        expect(decoded.keyCertSign).toBe(true)
        expect(decoded.cRLSign).toBe(true)
        expect(decoded.encipherOnly).toBe(false)
        expect(decoded.decipherOnly).toBe(false)
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
        expect(decoded.digitalSignature).toBe(true)
        expect(decoded.nonRepudiation).toBe(true)
        expect(decoded.keyEncipherment).toBe(true)
        expect(decoded.dataEncipherment).toBe(true)
        expect(decoded.keyAgreement).toBe(true)
        expect(decoded.keyCertSign).toBe(true)
        expect(decoded.cRLSign).toBe(true)
        expect(decoded.encipherOnly).toBe(true)
        expect(decoded.decipherOnly).toBe(true)
    })

    it('should encode and decode all flags false', () => {
        const allFalse = new KeyUsage({})
        const asn1 = allFalse.toAsn1()
        const decoded = KeyUsage.fromAsn1(asn1)
        expect(decoded.digitalSignature).toBe(false)
        expect(decoded.nonRepudiation).toBe(false)
        expect(decoded.keyEncipherment).toBe(false)
        expect(decoded.dataEncipherment).toBe(false)
        expect(decoded.keyAgreement).toBe(false)
        expect(decoded.keyCertSign).toBe(false)
        expect(decoded.cRLSign).toBe(false)
        expect(decoded.encipherOnly).toBe(false)
        expect(decoded.decipherOnly).toBe(false)
    })

    it('should throw if ASN.1 is not a BitString', () => {
        expect(() => KeyUsage.fromAsn1({} as any)).toThrow(
            `Expected BitString for KeyUsage`,
        )
    })
})
