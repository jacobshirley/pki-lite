import { describe, expect, it } from 'vitest'
import { der, UniversalTag } from '../core/PkiBase.js'
import { Time } from './Time.js'

describe('Time', () => {
    it('uses UTCTime from 1950 to 2049', () => {
        const at = (iso: string) => new Time({ time: new Date(iso) }).toAsn1()
        expect(at('2049-12-31T23:59:59Z').is(UniversalTag.UTCTime)).toBe(true)
        expect(at('1999-01-01T00:00:00Z').is(UniversalTag.UTCTime)).toBe(true)
        expect(
            at('1949-12-31T23:59:59Z').is(UniversalTag.GeneralizedTime),
        ).toBe(true)
    })

    it('drops fractional seconds (RFC 5280 4.1.2.5)', () => {
        const block = new Time({
            time: new Date('2051-02-03T04:05:06.789Z'),
        }).toAsn1()
        expect(new TextDecoder().decode(block.content)).toBe('20510203040506Z')
    })

    it('uses GeneralizedTime from 2050 (RFC 5280 4.1.2.5)', () => {
        const block = new Time({
            time: new Date('2050-01-01T00:00:00Z'),
        }).toAsn1()
        expect(block.is(UniversalTag.GeneralizedTime)).toBe(true)
        expect(new TextDecoder().decode(block.content)).toBe('20500101000000Z')
    })

    it('reads both UTCTime and GeneralizedTime', () => {
        const date = new Date('2030-06-01T12:00:00Z')
        expect(Time.fromAsn1(der.utcTime(date)).time).toEqual(date)
        expect(Time.fromAsn1(der.generalizedTime(date)).time).toEqual(date)
    })

    it('rejects other types, naming the field when given', () => {
        expect(() => Time.fromAsn1(der.integer(1))).toThrow(
            'Invalid ASN.1 structure: expected UTCTime or GeneralizedTime',
        )
        expect(() => Time.fromAsn1(der.integer(1), 'notBefore')).toThrow(
            'Expected UTCTime or GeneralizedTime for notBefore',
        )
    })

    it('encodes a GeneralizedTime (2050 on) in whole seconds (RFC 5280 4.1.2.5.2)', () => {
        const der = new Time({
            time: new Date('2051-03-04T05:06:07.890Z'),
        }).toDer()
        expect(String.fromCharCode(...der)).toContain('20510304050607Z')
    })
})
