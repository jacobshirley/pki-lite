import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

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

    toAsn1(): Asn1BaseBlock {
        return new asn1js.PrintableString({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a PrintableString from an ASN.1 PrintableString structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): PrintableString {
        if (!(asn1 instanceof asn1js.PrintableString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected PrintableString',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex =
            asn1.valueBlock.valueHexView ||
            asn1.valueBlock.valueBeforeDecodeView

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 PrintableString',
            )
        }

        return new PrintableString({ value: new Uint8Array(valueHex) })
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
