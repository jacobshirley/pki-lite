import { describe, expect, it } from 'vitest'
import * as asn1js from 'asn1js'
import { encodeTime } from './Time.js'

describe('encodeTime', () => {
    it('uses UTCTime up to 2049', () => {
        expect(encodeTime(new Date('2049-12-31T23:59:59Z'))).toBeInstanceOf(
            asn1js.UTCTime,
        )
        expect(encodeTime(new Date('1999-01-01T00:00:00Z'))).toBeInstanceOf(
            asn1js.UTCTime,
        )
    })

    it('uses GeneralizedTime from 2050 (RFC 5280 4.1.2.5)', () => {
        const block = encodeTime(new Date('2050-01-01T00:00:00Z'))
        expect(block).toBeInstanceOf(asn1js.GeneralizedTime)
        expect(
            new TextDecoder().decode(new Uint8Array(block.toBER()).slice(2)),
        ).toBe('20500101000000Z')
    })
})
