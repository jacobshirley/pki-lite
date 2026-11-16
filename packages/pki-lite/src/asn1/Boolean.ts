import { Asn1Node, der, PkiBase } from '../core/PkiBase.js'

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

    toAsn1(): Asn1Node {
        return der.boolean(this.value)
    }

    /**
     * Creates a Boolean from an ASN.1 Boolean structure
     */
    static fromAsn1(asn1: Asn1Node): Boolean {
        return new Boolean({ value: der.readBoolean(asn1) })
    }

    toString() {
        return this.value.toString()
    }
}
