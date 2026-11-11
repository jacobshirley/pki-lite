import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 TeletexString (T61String) value.
 *
 * @asn
 * ```asn
 * TeletexString ::= <value>
 * ```
 */
export class TeletexString extends PkiBase<TeletexString> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | TeletexString
    }) {
        super()
        const { value } = options

        if (value instanceof TeletexString) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1Node {
        return der.primitive(UniversalTag.TeletexString, this.bytes)
    }

    /**
     * Creates a TeletexString from an ASN.1 TeletexString structure
     */
    static fromAsn1(asn1: Asn1Node): TeletexString {
        return new TeletexString({
            value: asn1
                .expect(UniversalTag.TeletexString, 'TeletexString')
                .bytes(),
        })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the TeletexString to a hexadecimal string
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('')
    }
}
