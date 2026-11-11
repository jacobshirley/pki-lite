import { asn1js } from '../core/PkiBase.js'

/**
 * Encodes a date as the X.509 `Time` CHOICE.
 *
 * ```asn
 * Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
 * ```
 *
 * RFC 5280 4.1.2.5: dates up to and including 2049 are UTCTime; "in no case shall
 * UTCTime be used for representing dates beyond 2049" because its two-digit year makes
 * 50 ambiguous between 1950 and 2050. From 2050 on, GeneralizedTime is used.
 */
export function encodeTime(
    date: Date,
): asn1js.UTCTime | asn1js.GeneralizedTime {
    const utcTimeCutoff = new Date('2050-01-01T00:00:00.000Z')
    return date < utcTimeCutoff
        ? new asn1js.UTCTime({ valueDate: date })
        : new asn1js.GeneralizedTime({ valueDate: date })
}
