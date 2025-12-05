import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the validity period of a certificate.
 *
 * @asn
 * ```asn
 * Validity ::= SEQUENCE {
 *      notBefore      Time,
 *      notAfter       Time
 * }
 * ```
 */
export class Validity extends PkiBase<Validity> {
    notBefore: Date
    notAfter: Date

    constructor(options: { notBefore: Date; notAfter: Date }) {
        super()

        const { notBefore, notAfter } = options

        this.notBefore = notBefore
        this.notAfter = notAfter
    }

    /**
     * Converts the validity period to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.UTCTime({
                    valueDate: this.notBefore,
                }),
                new asn1js.UTCTime({
                    valueDate: this.notAfter,
                }),
            ],
        })
    }

    /**
     * Creates a Validity from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns A Validity
     */
    static fromAsn1(asn1: asn1js.BaseBlock): Validity {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('Expected Sequence')
        }

        if (asn1.valueBlock.value.length !== 2) {
            throw new Asn1ParseError('Expected 2 elements in Validity sequence')
        }

        const notBeforeBlock = asn1.valueBlock.value[0]
        const notAfterBlock = asn1.valueBlock.value[1]

        let notBefore: Date
        let notAfter: Date

        if (notBeforeBlock instanceof asn1js.UTCTime) {
            notBefore = notBeforeBlock.toDate() ?? new Date()
        } else if (notBeforeBlock instanceof asn1js.GeneralizedTime) {
            notBefore = notBeforeBlock.toDate() ?? new Date()
        } else {
            throw new Asn1ParseError(
                'Expected UTCTime or GeneralizedTime for notBefore',
            )
        }

        if (notAfterBlock instanceof asn1js.UTCTime) {
            notAfter = notAfterBlock.toDate() ?? new Date()
        } else if (notAfterBlock instanceof asn1js.GeneralizedTime) {
            notAfter = notAfterBlock.toDate() ?? new Date()
        } else {
            throw new Asn1ParseError(
                'Expected UTCTime or GeneralizedTime for notAfter',
            )
        }

        return new Validity({ notBefore, notAfter })
    }
}
