import { describe, expect, it } from 'vitest'
import * as asn1js from 'asn1js'
import { Time } from './Time.js'

describe('Time', () => {
    it('uses UTCTime up to 2049', () => {
        expect(
            new Time({ time: new Date('2049-12-31T23:59:59Z') }).toAsn1(),
        ).toBeInstanceOf(asn1js.UTCTime)
        expect(
            new Time({ time: new Date('1999-01-01T00:00:00Z') }).toAsn1(),
        ).toBeInstanceOf(asn1js.UTCTime)
    })

    it('uses GeneralizedTime from 2050 (RFC 5280 4.1.2.5)', () => {
        const block = new Time({
            time: new Date('2050-01-01T00:00:00Z'),
        }).toAsn1()
        expect(block).toBeInstanceOf(asn1js.GeneralizedTime)
        expect(
            new TextDecoder().decode(new Uint8Array(block.toBER()).slice(2)),
        ).toBe('20500101000000Z')
    })

    it('reads both UTCTime and GeneralizedTime', () => {
        const date = new Date('2030-06-01T12:00:00Z')
        expect(
            Time.fromAsn1(new asn1js.UTCTime({ valueDate: date })).time,
        ).toEqual(date)
        expect(
            Time.fromAsn1(new asn1js.GeneralizedTime({ valueDate: date })).time,
        ).toEqual(date)
    })

    it('rejects other types, naming the field when given', () => {
        expect(() => Time.fromAsn1(new asn1js.Integer({ value: 1 }))).toThrow(
            'Invalid ASN.1 structure: expected UTCTime or GeneralizedTime',
        )
        expect(() =>
            Time.fromAsn1(new asn1js.Integer({ value: 1 }), 'notBefore'),
        ).toThrow('Expected UTCTime or GeneralizedTime for notBefore')
    })

    it('encodes a GeneralizedTime (2050 on) in whole seconds (RFC 5280 4.1.2.5.2)', () => {
        const der = new Time({
            time: new Date('2051-03-04T05:06:07.890Z'),
        }).toDer()
        expect(String.fromCharCode(...der)).toContain('20510304050607Z')
    })
})
