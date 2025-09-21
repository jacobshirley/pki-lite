import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 TeletexString (T61String) value.
 *
 * @asn
 * ```asn
 * TeletexString ::= <value>
 * ```
 */
export class TeletexString extends PkiBase<TeletexString> {
    bytes: Uint8Array

    constructor(options: { value: string | Uint8Array | TeletexString }) {
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

    toAsn1(): Asn1BaseBlock {
        return new asn1js.TeletexString({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a TeletexString from an ASN.1 TeletexString structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): TeletexString {
        if (!(asn1 instanceof asn1js.TeletexString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected TeletexString',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex =
            asn1.valueBlock.valueHexView ||
            asn1.valueBlock.valueBeforeDecodeView

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 TeletexString',
            )
        }

        return new TeletexString({ value: new Uint8Array(valueHex) })
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
