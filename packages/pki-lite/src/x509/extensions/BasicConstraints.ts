import { asn1js, PkiBase } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the BasicConstraints extension.
 *
 * @asn
 * ```asn
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL
 * }
 * ```
 */
export class BasicConstraints extends PkiBase<BasicConstraints> {
    cA: boolean
    pathLenConstraint?: number

    constructor(options: { cA: boolean; pathLenConstraint?: number }) {
        super()

        const { cA, pathLenConstraint } = options

        this.cA = cA
        this.pathLenConstraint = pathLenConstraint
    }

    /**
     * Converts the BasicConstraints to an ASN.1 structure.
     */
    toAsn1() {
        const values = []

        values.push(new asn1js.Boolean({ value: this.cA }))

        if (this.pathLenConstraint !== undefined) {
            values.push(new asn1js.Integer({ value: this.pathLenConstraint }))
        }

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a BasicConstraints from an ASN.1 structure
     */
    static fromAsn1(asn1: asn1js.Sequence) {
        const sequence = asn1.valueBlock.value

        if (sequence.length === 0) {
            throw new Asn1ParseError('Invalid BasicConstraints ASN.1 structure')
        }

        const cA = sequence[0]
        if (!(cA instanceof asn1js.Boolean)) {
            throw new Asn1ParseError(
                'Invalid BasicConstraints ASN.1 structure: cA is not a Boolean',
            )
        }

        let pathLenConstraint: number | undefined
        if (sequence.length > 1) {
            const plc = sequence[1]
            if (!(plc instanceof asn1js.Integer)) {
                throw new Asn1ParseError(
                    'Invalid BasicConstraints ASN.1 structure: pathLenConstraint is not an Integer',
                )
            }
            pathLenConstraint = plc.valueBlock.valueDec
        }

        return new BasicConstraints({
            cA: cA.valueBlock.value,
            pathLenConstraint,
        })
    }
}
