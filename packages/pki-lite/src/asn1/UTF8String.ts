import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * Represents an ASN.1 UTF8String value.
 *
 * @asn
 * ```asn
 * UTF8String ::= <value>
 * ```
 */
export class UTF8String extends PkiBase<UTF8String> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | UTF8String
    }) {
        super()
        const { value } = options

        if (value instanceof UTF8String) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1Node {
        return der.primitive(UniversalTag.UTF8String, this.bytes)
    }

    /**
     * Creates a UTF8String from an ASN.1 UTF8String structure
     */
    static fromAsn1(asn1: Asn1Node): UTF8String {
        return new UTF8String({
            value: asn1.expect(UniversalTag.UTF8String, 'UTF8String').bytes(),
        })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the UTF8String to a hexadecimal string
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }
}
