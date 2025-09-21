import { assert, describe, expect, test } from 'vitest'
import { Validity } from './Validity.js'
import { asn1js } from '../core/PkiBase.js'

describe('Validity', () => {
    test('can be created', () => {
        const notBefore = new Date('2025-01-01')
        const notAfter = new Date('2026-01-01')

        const validity = new Validity({
            notBefore: notBefore,
            notAfter: notAfter,
        })

        expect(validity).toBeInstanceOf(Validity)
        expect(validity.notBefore).toBe(notBefore)
        expect(validity.notAfter).toBe(notAfter)
    })

    test('can be converted to ASN.1', () => {
        const notBefore = new Date('2025-01-01')
        const notAfter = new Date('2026-01-01')

        const validity = new Validity({
            notBefore: notBefore,
            notAfter: notAfter,
        })
        const asn1 = validity.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        const [notBeforeBlock, notAfterBlock] = asn1.valueBlock.value

        expect(notBeforeBlock).toBeInstanceOf(asn1js.UTCTime)
        expect(notAfterBlock).toBeInstanceOf(asn1js.UTCTime)
    })

    test('handles different date formats', () => {
        // Test with date string
        const notBefore = new Date('January 1, 2025')
        const notAfter = new Date('December 31, 2025')

        const validity = new Validity({
            notBefore: notBefore,
            notAfter: notAfter,
        })

        expect(validity).toBeInstanceOf(Validity)
        expect(validity.notBefore).toBe(notBefore)
        expect(validity.notAfter).toBe(notAfter)

        // Verify toAsn1 works with these dates
        const asn1 = validity.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
    })

    test('can be parsed from ASN.1 with UTCTime', () => {
        const notBefore = new Date('2025-01-01')
        const notAfter = new Date('2026-01-01')

        // Create ASN.1 sequence with UTCTime values
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.UTCTime({ valueDate: notBefore }),
                new asn1js.UTCTime({ valueDate: notAfter }),
            ],
        })

        const validity = Validity.fromAsn1(asn1)
        expect(validity).toBeInstanceOf(Validity)

        // Compare dates by converting to ISO strings (to avoid millisecond precision differences)
        expect(validity.notBefore.toISOString().substring(0, 19)).toBe(
            notBefore.toISOString().substring(0, 19),
        )
        expect(validity.notAfter.toISOString().substring(0, 19)).toBe(
            notAfter.toISOString().substring(0, 19),
        )
    })

    test('can be parsed from ASN.1 with GeneralizedTime', () => {
        const notBefore = new Date('2025-01-01')
        const notAfter = new Date('2026-01-01')

        // Create ASN.1 sequence with GeneralizedTime values
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.GeneralizedTime({ valueDate: notBefore }),
                new asn1js.GeneralizedTime({ valueDate: notAfter }),
            ],
        })

        const validity = Validity.fromAsn1(asn1)
        expect(validity).toBeInstanceOf(Validity)

        // Compare dates by converting to ISO strings (to avoid millisecond precision differences)
        expect(validity.notBefore.toISOString().substring(0, 19)).toBe(
            notBefore.toISOString().substring(0, 19),
        )
        expect(validity.notAfter.toISOString().substring(0, 19)).toBe(
            notAfter.toISOString().substring(0, 19),
        )
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a sequence
        const asn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => Validity.fromAsn1(asn1)).toThrow('Expected Sequence')
    })

    test('throws an error when notBefore is not a valid time format', () => {
        // Create an ASN.1 sequence with an invalid notBefore field
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
                new asn1js.UTCTime({ valueDate: new Date() }),
            ],
        })

        expect(() => Validity.fromAsn1(asn1)).toThrow(
            'Expected UTCTime or GeneralizedTime for notBefore',
        )
    })

    test('throws an error when notAfter is not a valid time format', () => {
        // Create an ASN.1 sequence with an invalid notAfter field
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.UTCTime({ valueDate: new Date() }),
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })

        expect(() => Validity.fromAsn1(asn1)).toThrow(
            'Expected UTCTime or GeneralizedTime for notAfter',
        )
    })

    test('toString snapshot', () => {
        const notBefore = new Date('2024-01-01T00:00:00.000Z')
        const notAfter = new Date('2025-01-01T00:00:00.000Z')
        const validity = new Validity({
            notBefore: notBefore,
            notAfter: notAfter,
        })
        expect(validity.toString()).toMatchInlineSnapshot(`
          "[Validity] SEQUENCE :
            UTCTime : 2024-01-01T00:00:00.000Z
            UTCTime : 2025-01-01T00:00:00.000Z"
        `)
    })

    test('toPem snapshot', () => {
        const notBefore = new Date('2024-01-01T00:00:00.000Z')
        const notAfter = new Date('2025-01-01T00:00:00.000Z')
        const validity = new Validity({
            notBefore: notBefore,
            notAfter: notAfter,
        })
        expect(validity.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN VALIDITY-----
          MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFo=
          -----END VALIDITY-----"
        `)
    })
})
