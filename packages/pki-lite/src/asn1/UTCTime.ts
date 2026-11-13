import { GeneralizedTime as GeneralizedTimeValue } from './GeneralizedTime.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 UTCTime value.
 *
 * @asn
 * ```asn
 * UTCTime ::= <value>
 * ```
 */
export class UTCTime extends PkiBase<Date> {
    time: Date

    constructor(options: { time?: Date | string | number } = {}) {
        super()
        this.time = options.time ? new Date(options.time) : new Date()
    }

    toAsn1(): Asn1Node {
        return der.utcTime(this.time)
    }

    static fromAsn1(asn1: Asn1Node): UTCTime {
        asn1.expect(UniversalTag.UTCTime, 'UTCTime')
        return new UTCTime({ time: der.readTime(asn1) })
    }
}

/**
 * @deprecated A duplicate kept for compatibility with imports from `UTCTime.js`;
 * use `GeneralizedTime` from `./GeneralizedTime.js` (whose field is `time`).
 */
export class GeneralizedTime extends PkiBase<Date> {
    date: Date

    constructor(options: { date?: Date | string | number } = {}) {
        super()
        this.date = options.date ? new Date(options.date) : new Date()
    }

    toAsn1(): Asn1Node {
        return new GeneralizedTimeValue({ time: this.date }).toAsn1()
    }

    static fromAsn1(asn1: Asn1Node): GeneralizedTime {
        asn1.expect(UniversalTag.GeneralizedTime, 'GeneralizedTime')
        return new GeneralizedTime({ date: der.readTime(asn1) })
    }
}
