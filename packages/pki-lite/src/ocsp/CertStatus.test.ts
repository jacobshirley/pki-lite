import { describe, expect, it } from 'vitest'
import { CertStatus } from './CertStatus.js'
import { derToAsn1 } from '../core/PkiBase.js'

describe('CertStatus', () => {
    it('should create a CertStatus with good status', () => {
        const status = CertStatus.createGood()
        expect(status.status).toEqual('good')
        expect(status.revocationReason).toBeUndefined()
        expect(status.revocationTime).toBeUndefined()
    })

    it('should create a CertStatus with unknown status', () => {
        const status = CertStatus.createUnknown()
        expect(status.status).toEqual('unknown')
        expect(status.revocationReason).toBeUndefined()
        expect(status.revocationTime).toBeUndefined()
    })

    it('should create a CertStatus with revoked status', () => {
        const revocationTime = new Date()
        const reason = 1 // keyCompromise
        const status = CertStatus.createRevoked(revocationTime, reason)

        expect(status.status).toEqual('revoked')
        expect(status.revocationTime).toEqual(revocationTime)
        expect(status.revocationReason).toEqual(reason)
    })

    it('should convert to ASN.1 and back for good status', () => {
        const original = CertStatus.createGood()
        const asn1 = original.toAsn1()
        const parsed = CertStatus.fromAsn1(asn1)

        expect(parsed.status).toEqual('good')
        expect(parsed.revocationReason).toBeUndefined()
        expect(parsed.revocationTime).toBeUndefined()
    })

    it('should convert to ASN.1 and back for revoked status', () => {
        const revocationTime = new Date()
        const reason = 1 // keyCompromise
        const original = CertStatus.createRevoked(revocationTime, reason)

        const asn1 = original.toAsn1()
        const parsed = CertStatus.fromAsn1(asn1)

        expect(parsed.status).toEqual('revoked')
        expect(parsed.revocationTime).not.toBeUndefined()
        expect(parsed.revocationReason).toEqual(reason)
    })

    describe('encoding (RFC 6960: revoked [1] IMPLICIT RevokedInfo)', () => {
        const toHex = (b: Uint8Array) =>
            Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
        const fromHex = (hex: string) =>
            new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)))

        // [1] { GeneralizedTime "20261111124129Z", [0] { ENUMERATED 1 } }
        const revokedDer =
            'a116' +
            '180f' +
            toHex(new TextEncoder().encode('20261111124129Z')) +
            'a003' +
            '0a0101'

        it('writes the RevokedInfo fields directly inside [1]', () => {
            const status = CertStatus.createRevoked(
                new Date(Date.UTC(2026, 10, 11, 12, 41, 29)),
                1,
            )
            expect(toHex(status.toDer())).toBe(revokedDer)
        })

        it('parses a revoked status as written by OpenSSL', () => {
            const status = CertStatus.fromAsn1(derToAsn1(fromHex(revokedDer)))
            expect(status.status).toBe('revoked')
            expect(status.revocationTime?.toISOString()).toBe(
                '2026-11-11T12:41:29.000Z',
            )
            expect(status.revocationReason).toBe(1)
        })

        it('parses a revoked status without a reason', () => {
            const der =
                'a111180f' + toHex(new TextEncoder().encode('20261111124129Z'))
            const status = CertStatus.fromAsn1(derToAsn1(fromHex(der)))
            expect(status.revocationReason).toBeUndefined()
            expect(toHex(status.toDer())).toBe(der)
        })

        it('still parses the SEQUENCE-wrapped form written by earlier versions', () => {
            // [1] { SEQUENCE { GeneralizedTime } }
            const legacy =
                'a113' +
                '3011' +
                '180f' +
                toHex(new TextEncoder().encode('20261111124129Z'))
            const status = CertStatus.fromAsn1(derToAsn1(fromHex(legacy)))
            expect(status.status).toBe('revoked')
        })
    })
})
