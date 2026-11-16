import { describe, expect, test } from 'vitest'
import { der, UniversalTag } from '../core/PkiBase.js'
import { GeneralizedTime } from './GeneralizedTime.js'

describe('GeneralizedDate', () => {
    test('should create GeneralizedDate from Date object', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const generalizedDate = new GeneralizedTime({ time: testDate })

        expect(generalizedDate.time).toEqual(testDate)
        expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())
    })

    test('should create GeneralizedDate from ISO string', () => {
        const isoString = '2023-01-15T10:30:00.000Z'
        const generalizedDate = new GeneralizedTime({ time: isoString })

        expect(generalizedDate.time.toISOString()).toEqual(isoString)
    })

    test('should create GeneralizedDate from timestamp number', () => {
        const timestamp = 1673781000000 // 2023-01-15T10:30:00.000Z
        const generalizedDate = new GeneralizedTime({ time: timestamp })

        expect(generalizedDate.time.getTime()).toEqual(timestamp)
    })

    test('should convert to ASN.1 GeneralizedTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const generalizedDate = new GeneralizedTime({ time: testDate })
        const asn1 = generalizedDate.toAsn1()

        expect(asn1.is(UniversalTag.GeneralizedTime)).toBe(true)

        // Verify the date is preserved
        expect(der.readTime(asn1).getTime()).toEqual(testDate.getTime())
    })

    test('should parse from ASN.1 GeneralizedTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const asn1 = der.generalizedTime(testDate)

        const generalizedDate = GeneralizedTime.fromAsn1(asn1)

        expect(generalizedDate).toBeInstanceOf(GeneralizedTime)
        expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = der.octetString(new Uint8Array([1, 2, 3]))

        expect(() => GeneralizedTime.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected GeneralizedTime',
        )
    })

    test('should handle dates beyond UTCTime range', () => {
        const futureDates = [
            new Date('2050-01-01T00:00:00.000Z'), // Beyond UTCTime range
            new Date('2100-12-31T23:59:59.000Z'),
            new Date('1950-01-01T00:00:00.000Z'), // Before UTCTime range
        ]

        for (const testDate of futureDates) {
            const generalizedDate = new GeneralizedTime({ time: testDate })
            expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())

            // Should be able to convert to ASN.1
            const asn1 = generalizedDate.toAsn1()
            expect(asn1.is(UniversalTag.GeneralizedTime)).toBe(true)
        }
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testDates = [
            new Date('2023-01-15T10:30:00.000Z'),
            new Date('2050-01-01T00:00:00.000Z'),
            new Date('1950-01-01T00:00:00.000Z'),
            new Date('2100-12-31T23:59:59.000Z'),
        ]

        for (const testDate of testDates) {
            const original = new GeneralizedTime({ time: testDate })
            const asn1 = original.toAsn1()
            const decoded = GeneralizedTime.fromAsn1(asn1)

            expect(decoded.time.getTime()).toEqual(testDate.getTime())
        }
    })

    test('keeps milliseconds in memory but encodes whole seconds', () => {
        const testDate = new Date('2023-01-15T10:30:00.123Z')
        const generalizedDate = new GeneralizedTime({ time: testDate })

        expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())

        // RFC 5280 4.1.2.5.2: no fractional seconds in the encoding
        const decoded = GeneralizedTime.fromAsn1(generalizedDate.toAsn1())
        expect(decoded.time.toISOString()).toEqual('2023-01-15T10:30:00.000Z')
    })

    test('encodes whole seconds, dropping milliseconds (RFC 5280 4.1.2.5.2)', () => {
        const time = new GeneralizedTime({
            time: new Date('2026-11-13T08:03:23.166Z'),
        })
        const text = new TextDecoder().decode(time.toAsn1().bytes())
        expect(text).toBe('20261113080323Z')
    })
})
