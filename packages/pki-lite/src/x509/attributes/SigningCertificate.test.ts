import { describe, it, expect } from 'vitest'
import { asn1js } from '../../core/PkiBase.js'
import { SigningCertificate, ESSCertID } from './SigningCertificate.js'
import { PolicyInformation, PolicyQualifierInfo } from '../PolicyInformation.js'
import { Name } from '../Name.js'
import { Integer } from '../../asn1/Integer.js'
import { UTF8String } from '../../asn1/UTF8String.js'
import { IssuerSerial } from '../IssuerSerial.js'

function makeIssuerSerial(): IssuerSerial {
    const emptyRdn = new asn1js.Sequence({ value: [] })
    const name = Name.fromAsn1(emptyRdn)
    return new IssuerSerial({
        issuer: name,
        serialNumber: new Integer({ value: 1 }),
    })
}

describe('ESSCertID', () => {
    it('round-trips with just certHash', () => {
        const ess = new ESSCertID({ certHash: new Uint8Array([1, 2, 3]) })
        const asn1 = ess.toAsn1()
        const round = ESSCertID.fromAsn1(asn1)
        expect(round.certHash.bytes).toEqual(new Uint8Array([1, 2, 3]))
        expect(round.issuerSerial).toBeUndefined()
    })

    it('round-trips with issuerSerial', () => {
        const ess = new ESSCertID({
            certHash: new Uint8Array([9]),
            issuerSerial: makeIssuerSerial(),
        })
        const asn1 = ess.toAsn1()
        const round = ESSCertID.fromAsn1(asn1)
        expect(round.certHash.bytes).toEqual(new Uint8Array([9]))
        expect(round.issuerSerial?.serialNumber.toNumber()).toBe(1)
    })

    it('throws when certHash is not OCTET STRING', () => {
        const bad = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 5 })],
        })
        expect(() => ESSCertID.fromAsn1(bad)).toThrow(
            'Invalid ESSCertID: expected OCTET STRING for certHash',
        )
    })
})

describe('SigningCertificate', () => {
    it('encodes with certs only', () => {
        const ess = new ESSCertID({ certHash: new Uint8Array([1]) })
        const sc = new SigningCertificate({ certs: [ess] })
        const asn1 = sc.toAsn1()
        const round = SigningCertificate.fromAsn1(asn1)
        expect(round.certs.length).toBe(1)
        expect(round.policies).toBeUndefined()
    })

    it('encodes with certs and policies', () => {
        const ess = new ESSCertID({ certHash: new Uint8Array([2]) })
        const pq = new PolicyQualifierInfo({
            policyQualifierId: '1.3.6.1.5.5.7.2.1',
            qualifier: new UTF8String({ value: 'CPS' }).toAsn1(),
        })
        const pi = new PolicyInformation({
            policyIdentifier: '2.5.29.32.0',
            policyQualifiers: [pq],
        })
        const sc = new SigningCertificate({ certs: [ess], policies: [pi] })
        const asn1 = sc.toAsn1()
        const round = SigningCertificate.fromAsn1(asn1)
        expect(round.certs.length).toBe(1)
        expect(round.policies?.length).toBe(1)
        expect(round.policies?.[0].policyIdentifier.value).toBe('2.5.29.32.0')
    })

    it('throws for non-sequence', () => {
        expect(() => SigningCertificate.fromAsn1(new asn1js.Null())).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('throws when certs is not a sequence', () => {
        const bad = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })
        expect(() => SigningCertificate.fromAsn1(bad)).toThrow(
            'Invalid SigningCertificate: expected SEQUENCE for certs',
        )
    })

    it('throws when policies is not a sequence', () => {
        const ess = new ESSCertID({ certHash: new Uint8Array([3]) })
        const bad = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [ess.toAsn1()] }),
                new asn1js.Integer({ value: 2 }),
            ],
        })
        expect(() => SigningCertificate.fromAsn1(bad)).toThrow(
            'Invalid SigningCertificate: expected SEQUENCE for policies',
        )
    })
})
