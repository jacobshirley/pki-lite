import { describe, expect, test } from 'vitest'
import { CertificatePolicies } from './CertificatePolicies.js'
import { PolicyInformation, PolicyQualifierInfo } from '../PolicyInformation.js'
import { asn1js, derToAsn1 } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('CertificatePolicies', () => {
    test('holds policies in order', () => {
        const policies = new CertificatePolicies(
            new PolicyInformation({ policyIdentifier: '1.2.3.4' }),
            new PolicyInformation({ policyIdentifier: '2.5.29.32.0' }),
        )
        expect(policies.policyIdentifiers).toEqual(['1.2.3.4', '2.5.29.32.0'])
    })

    test('encodes as a SEQUENCE OF PolicyInformation', () => {
        const policies = new CertificatePolicies(
            new PolicyInformation({ policyIdentifier: '1.2.3.4' }),
        )
        // SEQUENCE { SEQUENCE { OID 1.2.3.4 } }
        expect(hex(policies.toDer())).toBe('3007300506032a0304')
    })

    test('round-trips through DER, qualifiers included', () => {
        const cps = new asn1js.IA5String({ value: 'https://example.com/cps' })
        const policies = new CertificatePolicies(
            new PolicyInformation({
                policyIdentifier: '1.2.3.4',
                policyQualifiers: [
                    new PolicyQualifierInfo({
                        policyQualifierId: '1.3.6.1.5.5.7.2.1', // id-qt-cps
                        qualifier: cps.toBER(false) as never,
                    }),
                ],
            }),
            new PolicyInformation({ policyIdentifier: '1.2.3.5' }),
        )
        const der = policies.toDer()
        const parsed = CertificatePolicies.fromAsn1(derToAsn1(der))

        expect(parsed.policyIdentifiers).toEqual(['1.2.3.4', '1.2.3.5'])
        expect(parsed[0].policyQualifiers).toHaveLength(1)
        expect(parsed[1].policyQualifiers).toBeUndefined()
        expect(hex(parsed.toDer())).toBe(hex(der))
    })

    test('rejects anything but a SEQUENCE', () => {
        expect(() =>
            CertificatePolicies.fromAsn1(new asn1js.Integer({ value: 1 })),
        ).toThrow(Asn1ParseError)
    })
})
