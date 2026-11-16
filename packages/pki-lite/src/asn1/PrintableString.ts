import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 PrintableString value.
 *
 * @asn
 * ```asn
 * PrintableString ::= <value>
 * ```
 */
export class PrintableString extends PkiBase<PrintableString> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | PrintableString
    }) {
        super()
        const { value } = options

        if (value instanceof PrintableString) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1Node {
        return der.primitive(UniversalTag.PrintableString, this.bytes)
    }

    /**
     * Creates a PrintableString from an ASN.1 PrintableString structure
     */
    static fromAsn1(asn1: Asn1Node): PrintableString {
        return new PrintableString({
            value: asn1
                .expect(UniversalTag.PrintableString, 'PrintableString')
                .bytes(),
        })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the PrintableString to a hexadecimal string
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }
}
