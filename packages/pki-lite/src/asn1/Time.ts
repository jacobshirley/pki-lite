import { GeneralizedTime } from './GeneralizedTime.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
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

    toAsn1(): asn1js.UTCTime | asn1js.GeneralizedTime {
        const utcTimeCutoff = new Date('2050-01-01T00:00:00.000Z')
        return this.time < utcTimeCutoff
            ? new asn1js.UTCTime({ valueDate: this.time })
            : new GeneralizedTime({ time: this.time }).toAsn1()
    }

    /**
     * @param asn1 A UTCTime or GeneralizedTime
     * @param fieldName Names the field in the error message, e.g. `notBefore`
     */
    static fromAsn1(asn1: Asn1BaseBlock, fieldName?: string): Time {
        if (
            !(asn1 instanceof asn1js.UTCTime) &&
            !(asn1 instanceof asn1js.GeneralizedTime)
        ) {
            throw new Asn1ParseError(
                fieldName
                    ? `Expected UTCTime or GeneralizedTime for ${fieldName}`
                    : 'Invalid ASN.1 structure: expected UTCTime or GeneralizedTime',
            )
        }
        return new Time({ time: asn1.toDate() })
    }
}
