import { BitString } from '../asn1/BitString.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    derToAsn1,
    pemToDer,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an EC key. The structure follows X9.62 format.
 *
 * ASN.1 Structure:
 * ```
 * ECPublicKey ::= BIT STRING
 * ```
 *
 * Note: ECPublicKey is typically used within a SubjectPublicKeyInfo structure
 * where it appears as the BIT STRING component of the key.
 * The actual encoding is the uncompressed point format:
 * 0x04 || x || y
 * where 0x04 indicates uncompressed format, followed by the x and y coordinates.
 */
export class ECPublicKey extends BitString {
    /**
     * Creates a new ECPublicKey
     *
     * @param options.value The key as a Uint8Array in uncompressed format (0x04 || x || y)
     */
    constructor(options: { value: Uint8Array }) {
        super(options)
        // Validate the raw input
        if (this.bytes.length < 2 || this.bytes[0] !== 0x04) {
            throw new Asn1ParseError(
                'Invalid ECPublicKey: expected uncompressed point format (0x04)',
            )
        }
        this.bytes = options.value
    }

    toRaw(): Uint8Array {
        return this.bytes
    }

    static fromRaw(raw: Uint8Array): ECPublicKey {
        return new ECPublicKey({ value: raw })
    }

    /**
     * Creates an ECPublicKey from the X and Y coordinates of the point
     *
     * @param x The X coordinate of the point
     * @param y The Y coordinate of the point
     * @returns An ECPublicKey object
     */
    static fromCoordinates(x: Uint8Array, y: Uint8Array): ECPublicKey {
        // Create an uncompressed point: 0x04 || x || y
        const value = new Uint8Array(1 + x.length + y.length)
        value[0] = 0x04 // Uncompressed point format
        value.set(x, 1)
        value.set(y, 1 + x.length)

        return new ECPublicKey({ value })
    }

    /**
     * Extracts the X and Y coordinates from the key
     *
     * @returns An object containing the X and Y coordinates
     */
    getCoordinates(): { x: Uint8Array; y: Uint8Array } {
        // The X and Y coordinates have equal length
        const coordLength = (this.bytes.length - 1) / 2

        return {
            x: this.bytes.slice(1, 1 + coordLength),
            y: this.bytes.slice(1 + coordLength),
        }
    }
}
