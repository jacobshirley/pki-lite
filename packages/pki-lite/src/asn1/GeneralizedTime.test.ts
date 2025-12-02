import { describe, expect, test } from 'vitest'
import { GeneralizedTime } from './UTCTime.js'
import { asn1js } from '../core/PkiBase.js'

describe('GeneralizedDate', () => {
    test('should create GeneralizedDate from Date object', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const generalizedDate = new GeneralizedTime({ date: testDate })

        expect(generalizedDate.date).toEqual(testDate)
        expect(generalizedDate.date.getTime()).toEqual(testDate.getTime())
    })

    test('should create GeneralizedDate from ISO string', () => {
        const isoString = '2023-01-15T10:30:00.000Z'
        const generalizedDate = new GeneralizedTime({ date: isoString })

        expect(generalizedDate.date.toISOString()).toEqual(isoString)
    })

    test('should create GeneralizedDate from timestamp number', () => {
        const timestamp = 1673781000000 // 2023-01-15T10:30:00.000Z
        const generalizedDate = new GeneralizedTime({ date: timestamp })

        expect(generalizedDate.date.getTime()).toEqual(timestamp)
    })

    test('should convert to ASN.1 GeneralizedTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const generalizedDate = new GeneralizedTime({ date: testDate })
        const asn1 = generalizedDate.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.GeneralizedTime)

        // Verify the date is preserved
        const asn1GeneralizedTime = asn1 as asn1js.GeneralizedTime
        expect(asn1GeneralizedTime.toDate()!.getTime()).toEqual(
            testDate.getTime(),
        )
    })

    test('should parse from ASN.1 GeneralizedTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const asn1 = new asn1js.GeneralizedTime({ valueDate: testDate })

        const generalizedDate = GeneralizedTime.fromAsn1(asn1)

        expect(generalizedDate).toBeInstanceOf(GeneralizedTime)
        expect(generalizedDate.date.getTime()).toEqual(testDate.getTime())
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

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
            const generalizedDate = new GeneralizedTime({ date: testDate })
            expect(generalizedDate.date.getTime()).toEqual(testDate.getTime())

            // Should be able to convert to ASN.1
            const asn1 = generalizedDate.toAsn1()
            expect(asn1).toBeInstanceOf(asn1js.GeneralizedTime)
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
            const original = new GeneralizedTime({ date: testDate })
            const asn1 = original.toAsn1()
            const decoded = GeneralizedTime.fromAsn1(asn1)

            expect(decoded.date.getTime()).toEqual(testDate.getTime())
        }
    })

    test('should handle microsecond precision', () => {
        // GeneralizedTime can handle more precise timestamps
        const testDate = new Date('2023-01-15T10:30:00.123Z')
        const generalizedDate = new GeneralizedTime({ date: testDate })

        expect(generalizedDate.date.getTime()).toEqual(testDate.getTime())

        // Test round-trip
        const asn1 = generalizedDate.toAsn1()
        const decoded = GeneralizedTime.fromAsn1(asn1)
        expect(decoded.date.getTime()).toEqual(testDate.getTime())
    })
})
