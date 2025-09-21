import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 UTF8String value.
 *
 * @asn
 * ```asn
 * UTF8String ::= <value>
 * ```
 */
export class UTF8String extends PkiBase<UTF8String> {
    bytes: Uint8Array

    constructor(options: { value: string | Uint8Array | UTF8String }) {
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

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Utf8String({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a UTF8String from an ASN.1 UTF8String structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): UTF8String {
        if (!(asn1 instanceof asn1js.Utf8String)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected UTF8String',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex =
            asn1.valueBlock.valueHexView ||
            asn1.valueBlock.valueBeforeDecodeView

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 UTF8String',
            )
        }

        return new UTF8String({ value: new Uint8Array(valueHex) })
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
