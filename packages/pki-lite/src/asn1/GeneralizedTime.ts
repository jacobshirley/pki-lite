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

    toAsn1(): Asn1Node {
        return der.generalizedTime(this.time)
    }

    static fromAsn1(asn1: Asn1Node): GeneralizedTime {
        asn1.expect(UniversalTag.GeneralizedTime, 'GeneralizedTime')
        return new GeneralizedTime({ time: der.readTime(asn1) })
    }
}
