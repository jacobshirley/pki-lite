import { describe, expect, it } from 'vitest'
import { RevokedInfo } from './RevokedInfo.js'
import { asn1js } from '../core/PkiBase.js'
import { CRLReason } from '../x509/CRLReason.js'

describe('RevokedInfo', () => {
    it('should create a RevokedInfo with only revocation time', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const revokedInfo = new RevokedInfo({ revocationTime })

        expect(revokedInfo.revocationTime).toEqual(revocationTime)
        expect(revokedInfo.revocationReason).toBeUndefined()
    })

    it('should create a RevokedInfo with revocation time and reason', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const revocationReason = CRLReason.keyCompromise
        const revokedInfo = new RevokedInfo({
            revocationTime,
            revocationReason,
        })

        expect(revokedInfo.revocationTime).toEqual(revocationTime)
        expect(revokedInfo.revocationReason).toBe(revocationReason)
    })

    it('should create a RevokedInfo with different revocation reasons', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const reasons = [
            CRLReason.unspecified,
            CRLReason.cACompromise,
            CRLReason.affiliationChanged,
            CRLReason.superseded,
            CRLReason.cessationOfOperation,
            CRLReason.certificateHold,
            CRLReason.removeFromCRL,
            CRLReason.privilegeWithdrawn,
            CRLReason.aACompromise,
        ]

        for (const reason of reasons) {
            const revokedInfo = new RevokedInfo({
                revocationTime,
                revocationReason: reason,
            })
            expect(revokedInfo.revocationReason).toBe(reason)
        }
    })

    it('should convert to ASN.1 and back without revocation reason', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const original = new RevokedInfo({ revocationTime })

        const asn1 = original.toAsn1()
        const parsed = RevokedInfo.fromAsn1(asn1)

        expect(parsed.revocationTime).toBeDefined()
        expect(parsed.revocationReason).toBeUndefined()
        // Compare dates by converting to ISO strings (to avoid millisecond precision differences)
        expect(parsed.revocationTime.toISOString().substring(0, 19)).toBe(
            revocationTime.toISOString().substring(0, 19),
        )
    })

    it('should convert to ASN.1 and back with revocation reason', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const revocationReason = CRLReason.keyCompromise
        const original = new RevokedInfo({ revocationTime, revocationReason })

        const asn1 = original.toAsn1()
        const parsed = RevokedInfo.fromAsn1(asn1)

        expect(parsed.revocationTime).toBeDefined()
        expect(parsed.revocationReason).toEqual(revocationReason)
        // Compare dates by converting to ISO strings (to avoid millisecond precision differences)
        expect(parsed.revocationTime.toISOString().substring(0, 19)).toBe(
            revocationTime.toISOString().substring(0, 19),
        )
    })

    it('should convert to DER and back', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const revocationReason = CRLReason.certificateHold
        const original = new RevokedInfo({ revocationTime, revocationReason })

        const der = original.toDer()
        const parsed = RevokedInfo.fromDer(der)

        expect(parsed.revocationTime).toBeDefined()
        expect(parsed.revocationReason).toEqual(revocationReason)
        // Compare dates by converting to ISO strings (to avoid millisecond precision differences)
        expect(parsed.revocationTime.toISOString().substring(0, 19)).toBe(
            revocationTime.toISOString().substring(0, 19),
        )
    })

    it('should throw error on invalid ASN.1 structure', () => {
        const invalidAsn1 = {} as any

        expect(() => RevokedInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error on wrong number of elements', () => {
        const invalidAsn1 = {
            constructor: asn1js.Sequence,
            valueBlock: {
                value: [], // empty sequence
            },
        } as any
        Object.setPrototypeOf(invalidAsn1, asn1js.Sequence.prototype)

        expect(() => RevokedInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid RevokedInfo: expected 1 or 2 elements',
        )
    })

    it('should throw error on invalid revocation reason tag', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const validTimeAsn1 = new asn1js.GeneralizedTime({
            valueDate: revocationTime,
        })

        const invalidReasonContainer = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // CONTEXT-SPECIFIC
                tagNumber: 1, // [1] - wrong tag, should be [0]
            },
            value: [new asn1js.Enumerated({ value: 1 })],
        })

        const invalidAsn1 = new asn1js.Sequence({
            value: [validTimeAsn1, invalidReasonContainer],
        })

        expect(() => RevokedInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid RevokedInfo: expected [0] tag for revocationReason',
        )
    })

    it('should throw error on invalid enumerated for revocation reason', () => {
        const revocationTime = new Date('2025-01-15T10:30:00Z')
        const validTimeAsn1 = new asn1js.GeneralizedTime({
            valueDate: revocationTime,
        })

        const invalidReasonContainer = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // CONTEXT-SPECIFIC
                tagNumber: 0, // [0]
            },
            value: [new asn1js.Integer({ value: 1 })], // Should be Enumerated, not Integer
        })

        const invalidAsn1 = new asn1js.Sequence({
            value: [validTimeAsn1, invalidReasonContainer],
        })

        expect(() => RevokedInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected ENUMERATED for revocation reason',
        )
    })

    it('should handle various date formats', () => {
        const dates = [
            new Date('2025-01-01T00:00:00Z'),
            new Date('2025-12-31T23:59:59Z'),
            new Date('2030-06-15T12:30:45Z'),
        ]

        for (const date of dates) {
            const revokedInfo = new RevokedInfo({
                revocationTime: date,
                revocationReason: CRLReason.unspecified,
            })
            const asn1 = revokedInfo.toAsn1()
            const parsed = RevokedInfo.fromAsn1(asn1)

            expect(parsed.revocationTime).toBeDefined()
            // Compare dates by converting to ISO strings (to avoid millisecond precision differences)
            expect(parsed.revocationTime.toISOString().substring(0, 19)).toBe(
                date.toISOString().substring(0, 19),
            )
        }
    })
})
