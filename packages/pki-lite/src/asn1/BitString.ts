import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 BIT STRING value.
 *
 * @asn
 * ```asn
 * BIT STRING ::= <value>
 * ```
 */
export class BitString extends PkiBase<BitString> {
    bytes: Uint8Array

    constructor(options: { value: string | Uint8Array | BitString | PkiBase }) {
        super()
        const { value } = options

        if (value instanceof BitString) {
            this.bytes = value.bytes
        } else if (value instanceof Uint8Array) {
            this.bytes = value
        } else if (value instanceof PkiBase) {
            this.bytes = value.toDer()
        } else {
            this.bytes = new TextEncoder().encode(value)
        }
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.BitString({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a BitString from an ASN.1 BIT STRING structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): BitString {
        if (!(asn1 instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex =
            asn1.valueBlock.valueHexView ||
            asn1.valueBlock.valueBeforeDecodeView

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 BIT STRING',
            )
        }

        return new BitString({ value: new Uint8Array(valueHex) })
    }

    toString() {
        return new TextDecoder().decode(this.bytes)
    }

    /**
     * Converts the BitString to a hexadecimal string
     */
    toHexString(): string {
        return Array.from(this.bytes)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')
    }
}
