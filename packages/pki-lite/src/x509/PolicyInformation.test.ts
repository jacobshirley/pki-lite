import { describe, it, expect } from 'vitest'
import { PolicyInformation, PolicyQualifierInfo } from './PolicyInformation.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Any } from '../asn1/Any.js'
import { asn1js } from '../core/PkiBase.js'

describe('PolicyQualifierInfo', () => {
    it('should encode and decode ASN.1 correctly', () => {
        const pqid = '1.3.6.1.5.5.7.2.1' // id-qt-cps
        const qualifier = new Uint8Array([
            0x13,
            0x0b,
            ...new TextEncoder().encode('http://cps'),
        ])
        const pqInfo = new PolicyQualifierInfo({
            policyQualifierId: pqid,
            qualifier,
        })
        const asn1 = pqInfo.toAsn1()
        const decoded = PolicyQualifierInfo.fromAsn1(asn1)
        expect(decoded.policyQualifierId.value).toEqual(pqid)
        expect(decoded.qualifier.derBytes![0]).toEqual(0x13) // IA5String tag
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() => PolicyQualifierInfo.fromAsn1(new asn1js.Null())).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })
})

describe('PolicyInformation', () => {
    it('should encode and decode ASN.1 correctly (with qualifier)', () => {
        const pqid = '1.3.6.1.5.5.7.2.1'
        const qualifier = new Uint8Array([
            0x13,
            0x0b,
            ...new TextEncoder().encode('http://cps'),
        ])
        const pqInfo = new PolicyQualifierInfo({
            policyQualifierId: pqid,
            qualifier,
        })
        const pi = new PolicyInformation({
            policyIdentifier: '2.5.29.32.0',
            policyQualifiers: [pqInfo],
        })
        const asn1 = pi.toAsn1()
        const decoded = PolicyInformation.fromAsn1(asn1)
        expect(decoded.policyIdentifier.value).toEqual('2.5.29.32.0')
        expect(decoded.policyQualifiers).toBeDefined()
        expect(decoded.policyQualifiers?.length).toEqual(1)
        expect(decoded.policyQualifiers?.[0].policyQualifierId.value).toEqual(
            pqid,
        )
    })

    it('should encode and decode ASN.1 correctly (no qualifier)', () => {
        const pi = new PolicyInformation({
            policyIdentifier: '2.5.29.32.0',
        })
        const asn1 = pi.toAsn1()
        const decoded = PolicyInformation.fromAsn1(asn1)
        expect(decoded.policyIdentifier.value).toEqual('2.5.29.32.0')
        expect(decoded.policyQualifiers).toBeUndefined()
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() => PolicyInformation.fromAsn1(new asn1js.Null())).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })
})
