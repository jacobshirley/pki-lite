import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 GeneralizedTime value.
 *
 * @asn
 * ```asn
 * GeneralizedTime ::= <value>
 * ```
 */
export class GeneralizedTime extends PkiBase<Date> {
    time: Date

    constructor(options: { time?: Date | string | number } = {}) {
        super()
        this.time = options.time ? new Date(options.time) : new Date()
    }

    toAsn1() {
        return new asn1js.GeneralizedTime({ valueDate: this.time })
    }

    static fromAsn1(asn1: Asn1BaseBlock): GeneralizedTime {
        if (!(asn1 instanceof asn1js.GeneralizedTime)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected GeneralizedTime',
            )
        }
        const dateValue = asn1.toDate()
        return new GeneralizedTime({ time: dateValue ?? undefined })
    }
}
