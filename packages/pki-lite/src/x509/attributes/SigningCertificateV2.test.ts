import { describe, it, expect } from 'vitest'
import { asn1js } from '../../core/PkiBase.js'
import { ESSCertIDv2, SigningCertificateV2 } from './SigningCertificateV2.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { Name } from '../Name.js'
import { Integer } from '../../asn1/Integer.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { PolicyInformation, PolicyQualifierInfo } from '../PolicyInformation.js'
import { IssuerSerial } from '../IssuerSerial.js'

function makeIssuerSerial(): IssuerSerial {
    // Minimal RDNSequence/Name: use Name.fromAsn1 on an empty RDN sequence
    const emptyRdn = new asn1js.Sequence({ value: [] })
    const name = Name.fromAsn1(emptyRdn)
    return new IssuerSerial({
        issuer: name,
        serialNumber: new Integer({ value: 1 }),
    })
}

describe('ESSCertIDv2', () => {
    it('encodes and decodes with default hashAlgorithm omitted', () => {
        const certHash = new Uint8Array([1, 2, 3, 4])
        const ess = new ESSCertIDv2({ certHash })
        const asn1 = ess.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const round = ESSCertIDv2.fromAsn1(asn1)
        expect(round.hashAlgorithm).toBeUndefined()
        expect(round.certHash.bytes).toEqual(certHash)
        expect(round.issuerSerial).toBeUndefined()
    })

    it('encodes and decodes with all fields', () => {
        const alg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1' /* sha-256 */,
        })
        const certHash = new OctetString({ bytes: new Uint8Array([9, 9, 9]) })
        const ias = makeIssuerSerial()

        const ess = new ESSCertIDv2({
            hashAlgorithm: alg,
            certHash,
            issuerSerial: ias,
        })
        const asn1 = ess.toAsn1()

        const round = ESSCertIDv2.fromAsn1(asn1)
        expect(round.hashAlgorithm?.algorithm.value).toBe(
            '2.16.840.1.101.3.4.2.1',
        )
        expect(round.certHash.bytes).toEqual(new Uint8Array([9, 9, 9]))
        expect(round.issuerSerial?.serialNumber.toNumber()).toBe(1)
    })

    it('throws when certHash is not OCTET STRING', () => {
        const bad = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.3' }), // mistaken alg position but not a SEQUENCE
            ],
        })
        expect(() => ESSCertIDv2.fromAsn1(bad)).toThrow(
            'Invalid ESSCertIDv2: expected OCTET STRING for certHash',
        )
    })
})

describe('PolicyQualifierInfo', () => {
    it('round-trips toAsn1/fromAsn1', () => {
        const pq = new PolicyQualifierInfo({
            policyQualifierId: '1.3.6.1.5.5.7.2.1',
            qualifier: new asn1js.Utf8String({ value: 'CPS' }),
        })
        const asn1 = pq.toAsn1()
        const round = PolicyQualifierInfo.fromAsn1(asn1)
        expect(round.policyQualifierId.value).toBe('1.3.6.1.5.5.7.2.1')
        // We can only check that qualifier is Any; content is preserved as DER
        expect(round.qualifier.toAsn1()).toBeInstanceOf(asn1js.Utf8String)
    })

    it('throws for wrong element count', () => {
        const bad = new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: '1.2.3' })],
        })
        expect(() => PolicyQualifierInfo.fromAsn1(bad)).toThrow(
            'Invalid PolicyQualifierInfo: expected 2 elements',
        )
    })
})

describe('PolicyInformation', () => {
    it('encodes only policyIdentifier', () => {
        const pi = new PolicyInformation({ policyIdentifier: '1.2.3.4' })
        const asn1 = pi.toAsn1()
        const round = PolicyInformation.fromAsn1(asn1)
        expect(round.policyIdentifier.value).toBe('1.2.3.4')
        expect(round.policyQualifiers).toBeUndefined()
    })

    it('encodes with qualifiers', () => {
        const pq = new PolicyQualifierInfo({
            policyQualifierId: '1.2.3',
            qualifier: new asn1js.Utf8String({ value: 'ok' }),
        })
        const pi = new PolicyInformation({
            policyIdentifier: new ObjectIdentifier({ value: '1.2.3.4.5' }),
            policyQualifiers: [pq],
        })
        const asn1 = pi.toAsn1()
        const round = PolicyInformation.fromAsn1(asn1)
        expect(round.policyIdentifier.value).toBe('1.2.3.4.5')
        expect(round.policyQualifiers?.length).toBe(1)
        expect(round.policyQualifiers?.[0].policyQualifierId.value).toBe(
            '1.2.3',
        )
    })

    it('throws for wrong element count', () => {
        const bad = new asn1js.Sequence({ value: [] })
        expect(() => PolicyInformation.fromAsn1(bad)).toThrow(
            'Invalid PolicyInformation: expected 1 to 2 elements',
        )
    })
})

describe('SigningCertificateV2', () => {
    it('encodes with certs only', () => {
        const ess = new ESSCertIDv2({ certHash: new Uint8Array([1, 2, 3]) })
        const scv2 = new SigningCertificateV2({ certs: [ess] })
        const asn1 = scv2.toAsn1()
        const round = SigningCertificateV2.fromAsn1(asn1)
        expect(round.certs.length).toBe(1)
        expect(round.policies).toBeUndefined()
    })

    it('encodes with certs and policies', () => {
        const ess = new ESSCertIDv2({ certHash: new Uint8Array([1]) })
        const pq = new PolicyQualifierInfo({
            policyQualifierId: '1.3.6.1.5.5.7.2.1',
            qualifier: new asn1js.Utf8String({ value: 'CPS' }),
        })
        const pi = new PolicyInformation({
            policyIdentifier: '2.5.29.32.0',
            policyQualifiers: [pq],
        })
        const scv2 = new SigningCertificateV2({ certs: [ess], policies: [pi] })
        const asn1 = scv2.toAsn1()
        const round = SigningCertificateV2.fromAsn1(asn1)
        expect(round.certs.length).toBe(1)
        expect(round.policies?.length).toBe(1)
        expect(round.policies?.[0].policyIdentifier.value).toBe('2.5.29.32.0')
        expect(round.toString()).toMatchInlineSnapshot(`
      "[SigningCertificateV2] SEQUENCE :
        SEQUENCE :
          SEQUENCE :
            OCTET STRING : 01
        SEQUENCE :
          SEQUENCE :
            OBJECT IDENTIFIER : 2.5.29.32.0
            SEQUENCE :
              SEQUENCE :
                OBJECT IDENTIFIER : 1.3.6.1.5.5.7.2.1
                UTF8String : 'CPS'"
    `)
    })

    it('throws for non-sequence', () => {
        expect(() => SigningCertificateV2.fromAsn1(new asn1js.Null())).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('throws when certs is not a sequence', () => {
        const bad = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })
        expect(() => SigningCertificateV2.fromAsn1(bad)).toThrow(
            'Invalid SigningCertificateV2: expected SEQUENCE for certs',
        )
    })

    it('throws when policies is not a sequence', () => {
        const ess = new ESSCertIDv2({ certHash: new Uint8Array([1, 2]) })
        const bad = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({ value: [ess.toAsn1()] }),
                new asn1js.Integer({ value: 1 }),
            ],
        })
        expect(() => SigningCertificateV2.fromAsn1(bad)).toThrow(
            'Invalid SigningCertificateV2: expected SEQUENCE for policies',
        )
    })
})
