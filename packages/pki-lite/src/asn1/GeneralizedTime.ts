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
        this.time =
            options.time !== undefined ? new Date(options.time) : new Date()
    }

    /**
     * A copy at whole seconds, dropping any fraction (rounding down).
     *
     * GeneralizedTime may carry fractional seconds, but most profiles forbid them:
     * certificates and CRLs (RFC 5280 4.1.2.5.2), OCSP (RFC 6960), attribute certificates
     * (RFC 5755) and CMS signingTime (RFC 5652 11.3) require `YYYYMMDDHHMMSSZ`. Encode those
     * fields through this. RFC 3161 timestamps (TSTInfo genTime) may keep the fraction.
     *
     * @returns A new GeneralizedTime at the start of the same second
     */
    stripFractionalSeconds(): GeneralizedTime {
        const ms = this.time.getTime()
        return new GeneralizedTime({ time: ms - (((ms % 1000) + 1000) % 1000) })
    }

    /**
     * Encodes the time by the DER rules (X.690 11.7): UTC with a `Z`, seconds always
     * present, and fractional seconds (to the millisecond a Date holds) only when not
     * zero, without trailing zeros: `20261116120000Z`, `20261116120000.5Z`. Profiles that
     * forbid fractions call {@link stripFractionalSeconds} first.
     */
    toAsn1() {
        const iso = this.time.toISOString() // YYYY-MM-DDTHH:MM:SS.mmmZ
        const whole = iso.slice(0, 19).replace(/[-:T]/g, '')
        const fraction = iso.slice(20, 23).replace(/0+$/, '')
        return new asn1js.GeneralizedTime({
            value: `${whole}${fraction ? `.${fraction}` : ''}Z`,
        })
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
