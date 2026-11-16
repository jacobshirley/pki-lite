import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
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

    constructor(options: { cA?: boolean; pathLenConstraint?: number }) {
        super()

        const { cA = false, pathLenConstraint } = options

        this.cA = cA
        this.pathLenConstraint = pathLenConstraint
    }

    /**
     * Converts the BasicConstraints to an ASN.1 structure.
     *
     * DER forbids encoding a DEFAULT value, so `cA` is omitted when false
     * (`CA:FALSE` encodes as an empty SEQUENCE, as OpenSSL does).
     */
    toAsn1() {
        const values = []

        if (this.cA) {
            values.push(der.boolean(true))
        }

        if (this.pathLenConstraint !== undefined) {
            values.push(der.integer(this.pathLenConstraint))
        }

        return der.sequence(values)
    }

    /**
     * Creates a BasicConstraints from an ASN.1 structure
     *
     * Both fields are optional/defaulted, so an empty SEQUENCE (cA FALSE) and
     * a SEQUENCE holding only the pathLenConstraint are valid.
     */
    static fromAsn1(asn1: Asn1Node) {
        const sequence = asn1.children

        let index = 0
        let cA = false
        if (sequence[index]?.is(UniversalTag.Boolean)) {
            cA = der.readBoolean(sequence[index])
            index++
        }

        let pathLenConstraint: number | undefined
        if (index < sequence.length) {
            const plc = sequence[index]
            if (!plc.is(UniversalTag.Integer)) {
                throw new Asn1ParseError(
                    index === 0
                        ? 'Invalid BasicConstraints ASN.1 structure: cA is not a Boolean'
                        : 'Invalid BasicConstraints ASN.1 structure: pathLenConstraint is not an Integer',
                )
            }
            pathLenConstraint = der.readNumber(plc)
        }

        return new BasicConstraints({ cA, pathLenConstraint })
    }
}
