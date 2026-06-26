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

    it('should throw if BitString has no content', () => {
        const emptyBitString = new asn1js.BitString({
            valueHex: new ArrayBuffer(0),
        })
        expect(() => ReasonFlags.fromAsn1(emptyBitString)).toThrow(
            'ReasonFlags: BitString has no content',
        )
    })
})
