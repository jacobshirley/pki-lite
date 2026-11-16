import { describe, expect, test } from 'vitest'
import { GeneralizedTime } from './GeneralizedTime.js'
import * as asn1js from 'asn1js'
import { derToAsn1 } from '../core/PkiBase.js'

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

        expect(asn1).toBeInstanceOf(asn1js.GeneralizedTime)

        // Verify the date is preserved
        const asn1GeneralizedTime = asn1 as asn1js.GeneralizedTime
        expect(asn1GeneralizedTime.toDate().getTime()).toEqual(
            testDate.getTime(),
        )
    })

    test('should parse from ASN.1 GeneralizedTime correctly', () => {
        const testDate = new Date('2023-01-15T10:30:00.000Z')
        const asn1 = new asn1js.GeneralizedTime({ valueDate: testDate })

        const generalizedDate = GeneralizedTime.fromAsn1(asn1)

        expect(generalizedDate).toBeInstanceOf(GeneralizedTime)
        expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())
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
            const generalizedDate = new GeneralizedTime({ time: testDate })
            expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())

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
            const original = new GeneralizedTime({ time: testDate })
            const asn1 = original.toAsn1()
            const decoded = GeneralizedTime.fromAsn1(asn1)

            expect(decoded.time.getTime()).toEqual(testDate.getTime())
        }
    })

    test('keeps milliseconds in memory and in the encoding', () => {
        const testDate = new Date('2023-01-15T10:30:00.123Z')
        const generalizedDate = new GeneralizedTime({ time: testDate })

        expect(generalizedDate.time.getTime()).toEqual(testDate.getTime())
        const decoded = GeneralizedTime.fromAsn1(generalizedDate.toAsn1())
        expect(decoded.time.toISOString()).toEqual('2023-01-15T10:30:00.123Z')
        // RFC 5280 4.1.2.5.2 profiles strip them first
        const whole = GeneralizedTime.fromAsn1(
            generalizedDate.stripFractionalSeconds().toAsn1(),
        )
        expect(whole.time.toISOString()).toEqual('2023-01-15T10:30:00.000Z')
    })
})

/** The encoded value (`YYYYMMDDHHMMSS[.f]Z`) of a GeneralizedTime. */
const encoded = (time: GeneralizedTime) =>
    new TextDecoder().decode(
        (time.toAsn1() as asn1js.GeneralizedTime).valueBlock.valueHexView,
    )

describe('GeneralizedTime DER encoding (X.690 11.7)', () => {
    test('fractional seconds only when not zero, without trailing zeros', () => {
        const at = (ms: number) =>
            encoded(
                new GeneralizedTime({
                    time: Date.UTC(2026, 10, 16, 12, 0, 0, ms),
                }),
            )
        expect(at(0)).toBe('20261116120000Z')
        expect(at(500)).toBe('20261116120000.5Z')
        expect(at(120)).toBe('20261116120000.12Z')
        expect(at(7)).toBe('20261116120000.007Z')
        expect(at(999)).toBe('20261116120000.999Z')
    })

    test('the encoding parses back to the same time', () => {
        for (const ms of [0, 500, 120, 7]) {
            const time = new GeneralizedTime({
                time: Date.UTC(2026, 10, 16, 12, 0, 0, ms),
            })
            const der = time.toDer()
            const parsed = GeneralizedTime.fromAsn1(derToAsn1(der))
            expect(parsed.time).toEqual(time.time)
            expect(parsed.toDer()).toEqual(der)
        }
    })

    test('stripFractionalSeconds rounds down to whole seconds, as a copy', () => {
        const time = new GeneralizedTime({
            time: Date.UTC(2026, 10, 16, 12, 0, 0, 999),
        })
        const whole = time.stripFractionalSeconds()
        expect(encoded(whole)).toBe('20261116120000Z')
        expect(whole.time.toISOString()).toBe('2026-11-16T12:00:00.000Z')
        expect(time.time.getUTCMilliseconds()).toBe(999)

        // before 1970 too (negative epoch milliseconds)
        const old = new GeneralizedTime({ time: '1960-06-01T00:00:00.250Z' })
        expect(encoded(old.stripFractionalSeconds())).toBe('19600601000000Z')
    })

    test('the epoch (time 0) is kept, not replaced by now', () => {
        expect(encoded(new GeneralizedTime({ time: 0 }))).toBe(
            '19700101000000Z',
        )
    })
})
