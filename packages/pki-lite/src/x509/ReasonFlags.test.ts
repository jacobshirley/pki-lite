import { describe, it, expect } from 'vitest'
import { ReasonFlags } from './ReasonFlags.js'
import { asn1js } from '../core/PkiBase.js'

describe('ReasonFlags', () => {
    it('should encode and decode all flags set', () => {
        const flags = new ReasonFlags({
            unused: true,
            keyCompromise: true,
            cACompromise: true,
            affiliationChanged: true,
            superseded: true,
            cessationOfOperation: true,
            certificateHold: true,
            privilegeWithdrawn: true,
            aACompromise: true,
        })
        const asn1 = flags.toAsn1()
        const decoded = ReasonFlags.fromAsn1(asn1)
        expect(decoded.unused).toEqual(true)
        expect(decoded.keyCompromise).toEqual(true)
        expect(decoded.cACompromise).toEqual(true)
        expect(decoded.affiliationChanged).toEqual(true)
        expect(decoded.superseded).toEqual(true)
        expect(decoded.cessationOfOperation).toEqual(true)
        expect(decoded.certificateHold).toEqual(true)
        expect(decoded.privilegeWithdrawn).toEqual(true)
        expect(decoded.aACompromise).toEqual(true)
    })

    it('should encode and decode all flags false', () => {
        const flags = new ReasonFlags()
        const asn1 = flags.toAsn1()
        const decoded = ReasonFlags.fromAsn1(asn1)
        expect(decoded.unused).toEqual(false)
        expect(decoded.keyCompromise).toEqual(false)
        expect(decoded.cACompromise).toEqual(false)
        expect(decoded.affiliationChanged).toEqual(false)
        expect(decoded.superseded).toEqual(false)
        expect(decoded.cessationOfOperation).toEqual(false)
        expect(decoded.certificateHold).toEqual(false)
        expect(decoded.privilegeWithdrawn).toEqual(false)
        expect(decoded.aACompromise).toEqual(false)
    })

    it('should encode and decode a subset of flags', () => {
        const flags = new ReasonFlags({
            keyCompromise: true,
            certificateHold: true,
        })
        const asn1 = flags.toAsn1()
        const decoded = ReasonFlags.fromAsn1(asn1)
        expect(decoded.unused).toEqual(false)
        expect(decoded.keyCompromise).toEqual(true)
        expect(decoded.cACompromise).toEqual(false)
        expect(decoded.affiliationChanged).toEqual(false)
        expect(decoded.superseded).toEqual(false)
        expect(decoded.cessationOfOperation).toEqual(false)
        expect(decoded.certificateHold).toEqual(true)
        expect(decoded.privilegeWithdrawn).toEqual(false)
        expect(decoded.aACompromise).toEqual(false)
    })

    it('should encode unusedBits correctly', () => {
        const flags = new ReasonFlags({
            certificateHold: true,
            aACompromise: true,
        })

        const asn1 = flags.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.BitString)
        const bitString = asn1 as asn1js.BitString
        expect(bitString.valueBlock.unusedBits).toEqual(7)
        expect(Array.from(bitString.valueBlock.valueHexView)).toEqual([
            0b0000_0010, 0b1000_0000,
        ])
    })

    it('should decode unusedBits correctly', () => {
        const asn1 = new asn1js.BitString({
            valueHex: new Uint8Array([0b0000_0010, 0b1000_0000]).buffer,
            unusedBits: 7,
        })

        const decoded = ReasonFlags.fromAsn1(asn1)

        expect(decoded.cessationOfOperation).toEqual(false)
        expect(decoded.certificateHold).toEqual(true)
        expect(decoded.privilegeWithdrawn).toEqual(false)
        expect(decoded.aACompromise).toEqual(true)
    })

    it('should throw if ASN.1 is not a BitString', () => {
        expect(() => ReasonFlags.fromAsn1(new asn1js.Null())).toThrow(
            'ReasonFlags: Expected BitString for ReasonFlags',
        )
    })

    it('reads an empty BitString as no flags set', () => {
        const emptyBitString = new asn1js.BitString({
            valueHex: new ArrayBuffer(0),
        })
        const flags = ReasonFlags.fromAsn1(emptyBitString)
        expect(flags.keyCompromise).toBe(false)
        expect(flags.aACompromise).toBe(false)
    })

    it('encodes minimal DER: trailing zero bits are dropped', () => {
        const hex = (f: ReasonFlags) =>
            Array.from(f.toDer(), (b) => b.toString(16).padStart(2, '0')).join(
                '',
            )
        // keyCompromise (bit 1) -> 03 02 06 40
        expect(hex(new ReasonFlags({ keyCompromise: true }))).toBe('03020640')
        // aACompromise is bit 8, so a second byte is needed -> 03 03 07 00 80
        expect(hex(new ReasonFlags({ aACompromise: true }))).toBe('0303070080')
        // no bits -> empty BIT STRING
        expect(hex(new ReasonFlags({}))).toBe('030100')
    })
})
