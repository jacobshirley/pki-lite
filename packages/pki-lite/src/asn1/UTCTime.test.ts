import { describe, expect, test } from 'vitest'
import { UTCTime } from './UTCTime.js'
import * as asn1js from 'asn1js'

describe('UTCTime', () => {
    test('should create UTCTime from Date object', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const utcDate = new UTCTime({ time: testDate })

        expect(utcDate.time).toEqual(testDate)
        expect(utcDate.time.getTime()).toBe(testDate.getTime())
    })

    test('should create UTCTime from ISO string', () => {
        const isoString = '2023-01-15T10:30:00.000Z'
        const utcDate = new UTCTime({ time: isoString })

        expect(utcDate.time.toISOString()).toBe(isoString)
    })

    test('should create UTCTime from timestamp number', () => {
        const timestamp = 1673781000000 // 2023-01-15T10:30:00.000Z
        const utcDate = new UTCTime({ time: timestamp })

        expect(utcDate.time.getTime()).toBe(timestamp)
    })

    test('should convert to ASN.1 UTCTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const utcDate = new UTCTime({ time: testDate })
        const asn1 = utcDate.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.UTCTime)

        // Verify the date is preserved
        const asn1UtcTime = asn1 as asn1js.UTCTime
        expect(asn1UtcTime.toDate().getTime()).toBe(testDate.getTime())
    })

    test('should parse from ASN.1 UTCTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const asn1 = new asn1js.UTCTime({ valueDate: testDate })

        const utcDate = UTCTime.fromAsn1(asn1)

        expect(utcDate).toBeInstanceOf(UTCTime)
        expect(utcDate.time.getTime()).toBe(testDate.getTime())
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => UTCTime.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected UTCTime',
        )
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testDates = [
            new Date('2023-01-15T10:30:00.000Z'),
            new Date('2000-01-01T00:00:00.000Z'),
            new Date('2049-12-31T23:59:59.000Z'), // UTCTime range limit
        ]

        for (const testDate of testDates) {
            const original = new UTCTime({ time: testDate })
            const asn1 = original.toAsn1()
            const decoded = UTCTime.fromAsn1(asn1)

            expect(decoded.time.getTime()).toBe(testDate.getTime())
        }
    })
})
