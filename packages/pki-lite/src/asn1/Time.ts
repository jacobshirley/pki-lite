import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the X.509 `Time` CHOICE.
 *
 * RFC 5280 4.1.2.5: dates up to and including 2049 are encoded as UTCTime; "in no case
 * shall UTCTime be used for representing dates beyond 2049", because its two-digit year
 * makes 50 ambiguous between 1950 and 2050. From 2050 on GeneralizedTime is used.
 *
 * @asn
 * ```asn
 * Time ::= CHOICE {
 *      utcTime         UTCTime,
 *      generalTime     GeneralizedTime
 * }
 * ```
 */
export class Time extends PkiBase<Time> {
    time: Date

    constructor(options: { time: Date | string | number }) {
        super()
        this.time = new Date(options.time)
    }

    toAsn1(): Asn1Node {
        // RFC 5280 4.1.2.5: UTCTime for 1950-2049, GeneralizedTime otherwise;
        // neither carries fractional seconds
        const time = new Date(Math.floor(this.time.getTime() / 1000) * 1000)
        const year = time.getUTCFullYear()
        return year >= 1950 && year < 2050
            ? der.utcTime(time)
            : der.generalizedTime(time)
    }

    static fromAsn1(asn1: Asn1Node, fieldName?: string): Time {
        if (
            !asn1.is(UniversalTag.UTCTime) &&
            !asn1.is(UniversalTag.GeneralizedTime)
        ) {
            throw new Asn1ParseError(
                fieldName
                    ? `Expected UTCTime or GeneralizedTime for ${fieldName}`
                    : 'Invalid ASN.1 structure: expected UTCTime or GeneralizedTime',
            )
        }
        return new Time({ time: der.readTime(asn1) })
    }
}
