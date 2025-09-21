import * as asn1js from 'asn1js'
import { padUint8Array } from '../core/utils.js'
import { derToAsn1, PkiBase } from '../core/PkiBase.js'
import { Integer } from '../asn1/Integer.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ECDSA signature, consisting of r and s components.
 * This follows the ASN.1 structure:
 *
 * ECDSA-Sig-Value ::= SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 */
export class ECDSASignature extends PkiBase<ECDSASignature> {
    readonly r: Integer
    readonly s: Integer

    constructor(options: {
        r: Uint8Array | Integer | number
        s: Uint8Array | Integer | number
    }) {
        super()
        this.r = new Integer({ value: options.r })
        this.s = new Integer({ value: options.s })
    }

    /**
     * Convert to ASN.1 structure.
     *
     * Note: ASN.1 DER encoding requires that INTEGER values with the high bit set
     * are padded with a leading 0x00 byte to ensure they're interpreted as positive.
     * This is handled by the Integer class.
     */
    toAsn1(): asn1js.Sequence {
        return new asn1js.Sequence({
            value: [this.r.toAsn1(), this.s.toAsn1()],
        })
    }

    /**
     * Parse from ASN.1 structure.
     */
    static fromAsn1(asn1: asn1js.AsnType): ECDSASignature {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // Access valueBlock.value (need to cast due to type limitations)
        const values = (asn1 as any).valueBlock.value
        if (values.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements',
            )
        }

        const rAsn1 = values[0]
        const sAsn1 = values[1]

        if (!(rAsn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: r must be INTEGER',
            )
        }

        if (!(sAsn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: s must be INTEGER',
            )
        }

        const r = Integer.fromAsn1(rAsn1)
        const s = Integer.fromAsn1(sAsn1)

        return new ECDSASignature({ r, s })
    }

    /**
     * Parse from DER format.
     */
    static fromDer(der: Uint8Array): ECDSASignature {
        return this.fromAsn1(derToAsn1(der))
    }

    /**
     * Convert to raw format (r || s)
     */
    toRaw(): Uint8Array {
        let r = this.r.toUnsigned()
        let s = this.s.toUnsigned()
        const fixedLength = Math.max(r.length, s.length)

        // Pad with leading zeros
        r = padUint8Array(r, fixedLength)
        s = padUint8Array(s, fixedLength)

        // Concatenate r || s
        const raw = new Uint8Array(r.length + s.length)
        raw.set(r, 0)
        raw.set(s, r.length)

        return raw
    }

    /**
     * Parse from raw format (r || s).
     * @param raw Raw signature bytes (r || s)
     */
    static fromRaw(raw: Uint8Array): ECDSASignature {
        if (raw.length % 2 !== 0) {
            throw new Asn1ParseError(
                'Invalid raw ECDSA signature: length must be even',
            )
        }

        const componentLength = raw.length / 2
        const r = raw.slice(0, componentLength)
        const s = raw.slice(componentLength)

        return new ECDSASignature({ r, s })
    }
}
