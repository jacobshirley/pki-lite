import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 UniversalString value.
 *
 * @asn
 * ```asn
 * UniversalString ::= <value>
 * ```
 */
export class UniversalString extends PkiBase<UniversalString> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | UniversalString
    }) {
        super()
        const { value } = options

        if (value instanceof UniversalString) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1Node {
        return der.primitive(UniversalTag.UniversalString, this.bytes)
    }

    /**
     * Creates a UniversalString from an ASN.1 UniversalString structure
     */
    static fromAsn1(asn1: Asn1Node): UniversalString {
        return new UniversalString({
            value: asn1
                .expect(UniversalTag.UniversalString, 'UniversalString')
                .bytes(),
        })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the UniversalString to a hexadecimal string
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }
}
