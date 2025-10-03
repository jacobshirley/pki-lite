import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 BMPString value.
 *
 * @asn
 * ```asn
 * BMPString ::= <value>
 * ```
 */
export class BMPString extends PkiBase<BMPString> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: {
        value: string | Uint8Array<ArrayBuffer> | BMPString
    }) {
        super()
        const { value } = options

        if (value instanceof BMPString) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.BmpString({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a BMPString from an ASN.1 BMPString structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): BMPString {
        if (!(asn1 instanceof asn1js.BmpString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BMPString',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex = new TextEncoder().encode(asn1.valueBlock.value)

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 BMPString',
            )
        }

        return new BMPString({ value: new Uint8Array(valueHex) })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }
}
