import { describe, expect, test } from 'vitest'
import { PolicyConstraints } from './PolicyConstraints.js'
import { asn1js, derToAsn1 } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const fromHex = (h: string) =>
    new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)))

describe('PolicyConstraints', () => {
    test('both fields are optional', () => {
        const empty = new PolicyConstraints()
        expect(empty.requireExplicitPolicy).toBeUndefined()
        expect(empty.inhibitPolicyMapping).toBeUndefined()
        expect(hex(empty.toDer())).toBe('3000')
    })

    test('encodes the skip counts as [0]/[1] IMPLICIT INTEGERs', () => {
        expect(
            hex(new PolicyConstraints({ requireExplicitPolicy: 0 }).toDer()),
        ).toBe('3003800100')
        expect(
            hex(new PolicyConstraints({ inhibitPolicyMapping: 2 }).toDer()),
        ).toBe('3003810102')
        expect(
            hex(
                new PolicyConstraints({
                    requireExplicitPolicy: 1,
                    inhibitPolicyMapping: 3,
                }).toDer(),
            ),
        ).toBe('3006800101810103')
    })

    test('parses what OpenSSL writes', () => {
        const parsed = PolicyConstraints.fromAsn1(
            derToAsn1(fromHex('3006800101810103')),
        )
        expect(parsed.requireExplicitPolicy).toBe(1)
        expect(parsed.inhibitPolicyMapping).toBe(3)

        const onlyInhibit = PolicyConstraints.fromAsn1(
            derToAsn1(fromHex('3003810100')),
        )
        expect(onlyInhibit.requireExplicitPolicy).toBeUndefined()
        expect(onlyInhibit.inhibitPolicyMapping).toBe(0)
    })

    test('round-trips through DER', () => {
        const original = new PolicyConstraints({
            requireExplicitPolicy: 5,
            inhibitPolicyMapping: 300,
        })
        const der = original.toDer()
        const parsed = PolicyConstraints.fromAsn1(derToAsn1(der))
        expect(parsed.requireExplicitPolicy).toBe(5)
        expect(parsed.inhibitPolicyMapping).toBe(300)
        expect(hex(parsed.toDer())).toBe(hex(der))
    })

    test('rejects unexpected elements and non-SEQUENCEs', () => {
        expect(() =>
            PolicyConstraints.fromAsn1(derToAsn1(fromHex('3003020101'))),
        ).toThrow(Asn1ParseError)
        expect(() =>
            PolicyConstraints.fromAsn1(new asn1js.Integer({ value: 1 })),
        ).toThrow(Asn1ParseError)
    })
})
