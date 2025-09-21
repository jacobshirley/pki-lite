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
        expect(decoded.unused).toBe(true)
        expect(decoded.keyCompromise).toBe(true)
        expect(decoded.cACompromise).toBe(true)
        expect(decoded.affiliationChanged).toBe(true)
        expect(decoded.superseded).toBe(true)
        expect(decoded.cessationOfOperation).toBe(true)
        expect(decoded.certificateHold).toBe(true)
        expect(decoded.privilegeWithdrawn).toBe(true)
        expect(decoded.aACompromise).toBe(true)
    })

    it('should encode and decode all flags false', () => {
        const flags = new ReasonFlags()
        const asn1 = flags.toAsn1()
        const decoded = ReasonFlags.fromAsn1(asn1)
        expect(decoded.unused).toBe(false)
        expect(decoded.keyCompromise).toBe(false)
        expect(decoded.cACompromise).toBe(false)
        expect(decoded.affiliationChanged).toBe(false)
        expect(decoded.superseded).toBe(false)
        expect(decoded.cessationOfOperation).toBe(false)
        expect(decoded.certificateHold).toBe(false)
        expect(decoded.privilegeWithdrawn).toBe(false)
        expect(decoded.aACompromise).toBe(false)
    })

    it('should encode and decode a subset of flags', () => {
        const flags = new ReasonFlags({
            keyCompromise: true,
            certificateHold: true,
        })
        const asn1 = flags.toAsn1()
        const decoded = ReasonFlags.fromAsn1(asn1)
        expect(decoded.unused).toBe(false)
        expect(decoded.keyCompromise).toBe(true)
        expect(decoded.cACompromise).toBe(false)
        expect(decoded.affiliationChanged).toBe(false)
        expect(decoded.superseded).toBe(false)
        expect(decoded.cessationOfOperation).toBe(false)
        expect(decoded.certificateHold).toBe(true)
        expect(decoded.privilegeWithdrawn).toBe(false)
        expect(decoded.aACompromise).toBe(false)
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
