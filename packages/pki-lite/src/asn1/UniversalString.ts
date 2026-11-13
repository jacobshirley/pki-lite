import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

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
            this.bytes = encodeUtf32BE(value)
        }
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.UniversalString({
            valueHex: this.bytes,
        })
    }

    /**
     * Creates a UniversalString from an ASN.1 UniversalString structure
     */
    static fromAsn1(asn1: Asn1BaseBlock): UniversalString {
        if (!(asn1 instanceof asn1js.UniversalString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected UniversalString',
            )
        }

        // Get the binary data from the ASN.1 structure
        const valueHex =
            asn1.valueBlock.valueHexView ||
            asn1.valueBlock.valueBeforeDecodeView

        if (!valueHex) {
            throw new Asn1ParseError(
                'Could not extract value from ASN.1 UniversalString',
            )
        }

        return new UniversalString({ value: new Uint8Array(valueHex) })
    }

    /** Decodes the UTF-32BE content (UniversalString is UCS-4, X.680 41.4). */
    toString() {
        const view = new DataView(
            this.bytes.buffer,
            this.bytes.byteOffset,
            this.bytes.byteLength,
        )
        let result = ''
        for (let i = 0; i + 4 <= this.bytes.length; i += 4) {
            result += String.fromCodePoint(view.getUint32(i))
        }
        return result
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

function encodeUtf32BE(value: string): Uint8Array<ArrayBuffer> {
    const codePoints = Array.from(value, (char) => char.codePointAt(0)!)
    const bytes = new Uint8Array(codePoints.length * 4)
    const view = new DataView(bytes.buffer)
    codePoints.forEach((codePoint, i) => view.setUint32(i * 4, codePoint))
    return bytes
}
