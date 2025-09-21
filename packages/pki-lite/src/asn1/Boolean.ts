import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 BOOLEAN value.
 *
 * @asn
 * ```asn
 * Boolean ::= <value>
 * ```
 */
export class Boolean extends PkiBase<Boolean> {
    value: boolean

    constructor(options: { value: boolean }) {
        super()

        if (typeof options.value !== 'boolean') {
            throw new Error('Boolean value must be a boolean')
        }

        this.value = options.value
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Boolean({
            value: this.value,
        })
    }

    /**
     * Creates a Boolean from an ASN.1 Boolean structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): Boolean {
        if (!(asn1 instanceof asn1js.Boolean)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Boolean but got ' +
                    asn1.constructor.name,
            )
        }

        return new Boolean({ value: asn1.valueBlock.value })
    }

    toString() {
        return this.value.toString()
    }
}
