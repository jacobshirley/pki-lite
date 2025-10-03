import { describe, expect, it } from 'vitest'
import { CertStatus } from './CertStatus.js'

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
})
