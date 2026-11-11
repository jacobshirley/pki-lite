import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

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
            // Encode as UTF-16BE (UCS-2 big endian)
            this.bytes = stringToUtf16BE(value)
        }
    }

    /**
     * Converts a string to UTF-16BE (UCS-2 big endian) bytes.
     */
    static toUtf16BE(str: string): Uint8Array<ArrayBuffer> {
        return stringToUtf16BE(str)
    }

    /**
     * Converts a password to PKCS#12 form: BMPString (UTF-16BE) with a
     * trailing 16-bit NUL terminator.
     *
     * @param password The password (string or bytes)
     * @returns UTF-16BE encoded password with NUL terminator
     */
    static nullTerminated(
        password: string | Uint8Array<ArrayBuffer>,
    ): Uint8Array<ArrayBuffer> {
        const str =
            typeof password === 'string'
                ? password
                : new TextDecoder().decode(password)
        // Encode as UTF-16BE, then append NUL terminator
        const utf16be = stringToUtf16BE(str)
        const result = new Uint8Array(utf16be.length + 2)
        result.set(utf16be)
        // Last 2 bytes are already 0 (null terminator)
        return result
    }

    toAsn1(): Asn1Node {
        return der.primitive(UniversalTag.BMPString, this.bytes)
    }

    /**
     * Creates a BMPString from an ASN.1 BMPString structure
     */
    static fromAsn1(asn1: Asn1Node): BMPString {
        return new BMPString({
            value: asn1.expect(UniversalTag.BMPString, 'BMPString').bytes(),
        })
    }

    toString() {
        // Decode UTF-16BE to string
        let result = ''
        for (let i = 0; i < this.bytes.length; i += 2) {
            const code = (this.bytes[i] << 8) | this.bytes[i + 1]
            result += String.fromCharCode(code)
        }
        return result
    }
}

/**
 * Converts a string to UTF-16BE (UCS-2 big endian) bytes.
 */
function stringToUtf16BE(str: string): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(str.length * 2)
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i)
        bytes[i * 2] = (code >> 8) & 0xff
        bytes[i * 2 + 1] = code & 0xff
    }
    return bytes
}
