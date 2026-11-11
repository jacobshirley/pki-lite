import { describe, expect, test } from 'vitest'
import { PolicyMapping, PolicyMappings } from './PolicyMappings.js'
import { asn1js, derToAsn1 } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('PolicyMapping', () => {
    test('holds the issuer and subject domain policies', () => {
        const mapping = new PolicyMapping({
            issuerDomainPolicy: '1.2.3.4',
            subjectDomainPolicy: '1.2.3.5',
        })
        expect(mapping.issuerDomainPolicy.toString()).toBe('1.2.3.4')
        expect(mapping.subjectDomainPolicy.toString()).toBe('1.2.3.5')
    })

    test('encodes as a SEQUENCE of two OIDs', () => {
        const mapping = new PolicyMapping({
            issuerDomainPolicy: '1.2.3.4',
            subjectDomainPolicy: '1.2.3.5',
        })
        expect(hex(mapping.toDer())).toBe('300a06032a030406032a0305')
    })

    test('rejects a SEQUENCE without exactly two policies', () => {
        const one = new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: '1.2.3.4' })],
        })
        expect(() => PolicyMapping.fromAsn1(one)).toThrow(Asn1ParseError)
        expect(() =>
            PolicyMapping.fromAsn1(new asn1js.Integer({ value: 1 })),
        ).toThrow(Asn1ParseError)
    })
})

describe('PolicyMappings', () => {
    test('round-trips through DER', () => {
        const mappings = new PolicyMappings(
            new PolicyMapping({
                issuerDomainPolicy: '1.2.3.4',
                subjectDomainPolicy: '1.2.3.5',
            }),
            new PolicyMapping({
                issuerDomainPolicy: '1.2.3.4',
                subjectDomainPolicy: '1.2.3.6',
            }),
        )
        const der = mappings.toDer()
        const parsed = PolicyMappings.fromAsn1(derToAsn1(der))

        expect(parsed).toHaveLength(2)
        expect(parsed[1].subjectDomainPolicy.toString()).toBe('1.2.3.6')
        expect(hex(parsed.toDer())).toBe(hex(der))
    })

    test('exposes PolicyMapping', () => {
        expect(PolicyMappings.PolicyMapping).toBe(PolicyMapping)
    })

    test('rejects anything but a SEQUENCE', () => {
        expect(() =>
            PolicyMappings.fromAsn1(new asn1js.Integer({ value: 1 })),
        ).toThrow(Asn1ParseError)
    })
})
