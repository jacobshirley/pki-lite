import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

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
    toAsn1(): Asn1Node {
        const seconds = Math.floor(this.time.getTime() / 1000) * 1000
        return der.generalizedTime(new Date(seconds))
    }

    static fromAsn1(asn1: Asn1Node): GeneralizedTime {
        asn1.expect(UniversalTag.GeneralizedTime, 'GeneralizedTime')
        return new GeneralizedTime({ time: der.readTime(asn1) })
    }
}
