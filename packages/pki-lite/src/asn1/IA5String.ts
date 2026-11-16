import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 IA5String (Internationalized ASCII String) value.
 *
 * @asn
 * ```asn
 * IA5String ::= <value>
 * ```
 */
export class IA5String extends PkiBase<IA5String> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: { value: string | Uint8Array | IA5String }) {
        super()
        const { value } = options

        if (value instanceof IA5String) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = new Uint8Array(value)
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1Node {
        return der.primitive(UniversalTag.IA5String, this.bytes)
    }

    /**
     * Creates a IA5String from an ASN.1 IA5String structure
     */
    static fromAsn1(asn1: Asn1Node): IA5String {
        return new IA5String({
            value: asn1.expect(UniversalTag.IA5String, 'IA5String').bytes(),
        })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the IA5String to a hexadecimal string
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }
}
