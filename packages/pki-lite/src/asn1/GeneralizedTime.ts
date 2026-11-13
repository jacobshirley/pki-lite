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

    /**
     * Encodes the time as `YYYYMMDDHHMMSSZ`: in whole seconds, as RFC 5280 4.1.2.5.2
     * requires of the GeneralizedTime values in certificates, CRLs and OCSP (RFC 6960),
     * so any milliseconds are dropped.
     */
    toAsn1() {
        const seconds = Math.floor(this.time.getTime() / 1000) * 1000
        return new asn1js.GeneralizedTime({ valueDate: new Date(seconds) })
    }

    static fromAsn1(asn1: Asn1BaseBlock): GeneralizedTime {
        if (!(asn1 instanceof asn1js.GeneralizedTime)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected GeneralizedTime',
            )
        }
        return new GeneralizedTime({ time: asn1.toDate() })
    }
}
