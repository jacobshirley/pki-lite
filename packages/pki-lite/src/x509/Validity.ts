import { Time } from '../asn1/Time.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'
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
    toAsn1(): Asn1Node {
        const notBefore = new Time({ time: this.notBefore }).toAsn1()
        const notAfter = new Time({ time: this.notAfter }).toAsn1()

        return der.sequence([notBefore, notAfter])
    }

    /**
     * Creates a Validity from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns A Validity
     */
    static fromAsn1(asn1: Asn1Node): Validity {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError('Expected Sequence')
        }

        if (asn1.children.length !== 2) {
            throw new Asn1ParseError('Expected 2 elements in Validity sequence')
        }

        const notBeforeBlock = asn1.children[0]
        const notAfterBlock = asn1.children[1]

        const notBefore = Time.fromAsn1(notBeforeBlock, 'notBefore').time
        const notAfter = Time.fromAsn1(notAfterBlock, 'notAfter').time

        return new Validity({ notBefore, notAfter })
    }
}
