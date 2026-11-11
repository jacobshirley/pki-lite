import { describe, it, expect } from 'vitest'
import { KeyUsage } from './KeyUsage.js'
import { asn1js } from '../../core/PkiBase.js'

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

    it('should encode unusedBits correctly', () => {
        const usage = new KeyUsage({
            cRLSign: true,
            keyCertSign: true,
        })

        const asn1 = usage.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.BitString)
        const bitString = asn1 as asn1js.BitString
        // DER drops trailing zero bits: bits 0-6 are used, so 1 bit is unused
        expect(bitString.valueBlock.unusedBits).toEqual(1)
        expect(Array.from(bitString.valueBlock.valueHexView)).toEqual([
            0b0000_0110,
        ])
    })

    it('should decode unusedBits correctly', () => {
        const asn1 = new asn1js.BitString({
            valueHex: new Uint8Array([0b0000_0110, 0b0000_0000]).buffer,
            unusedBits: 7,
        })

        const decoded = KeyUsage.fromAsn1(asn1)

        expect(decoded.keyAgreement).toEqual(false)
        expect(decoded.cRLSign).toEqual(true)
        expect(decoded.keyCertSign).toEqual(true)
        expect(decoded.encipherOnly).toEqual(false)
        expect(decoded.decipherOnly).toEqual(false)
    })

    it('should throw if ASN.1 is not a BitString', () => {
        expect(() => KeyUsage.fromAsn1({} as any)).toThrow(
            `Expected BitString for KeyUsage`,
        )
    })

    it('encodes minimal DER: trailing zero bits are dropped', () => {
        const hex = (u: KeyUsage) =>
            Array.from(u.toDer(), (b) => b.toString(16).padStart(2, '0')).join(
                '',
            )
        // digitalSignature only -> 03 02 07 80
        expect(hex(new KeyUsage({ digitalSignature: true }))).toBe('03020780')
        // keyCertSign + cRLSign -> 03 02 01 06
        expect(hex(new KeyUsage({ keyCertSign: true, cRLSign: true }))).toBe(
            '03020106',
        )
        // decipherOnly is bit 8, so a second byte is needed -> 03 03 07 00 80
        expect(hex(new KeyUsage({ decipherOnly: true }))).toBe('0303070080')
        // no bits at all -> empty BIT STRING
        expect(hex(new KeyUsage({}))).toBe('030100')
    })
})
