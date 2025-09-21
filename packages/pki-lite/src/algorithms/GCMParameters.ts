import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'
import { Integer } from '../asn1/Integer.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents GCM Parameters as defined in RFC 5084.
 *
 * @asn
 * ```asn
 * GCMParameters ::= SEQUENCE {
 *   aes-nonce        OCTET STRING, -- recommended size is 12 octets
 *   aes-ICVlen       AES-GCM-ICVlen DEFAULT 12
 * }
 *
 * AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)
 * ```
 */
export class GCMParameters extends PkiBase<GCMParameters> {
    aesNonce: OctetString
    aesICVlen: Integer

    /**
     * Creates a new instance of GCMParameters
     *
     * @param options Configuration options for GCM parameters
     * @param options.aesNonce The nonce value (initialization vector). Recommended size is 12 octets.
     * @param options.aesICVlen The integrity check value length in octets (12, 13, 14, 15, or 16). Default is 12.
     */
    constructor(options: { aesNonce: Uint8Array; aesICVlen?: number }) {
        super()

        this.aesNonce = new OctetString({ bytes: options.aesNonce })

        // Validate and set ICVlen if provided
        const aesICVlen = options.aesICVlen ?? 12
        const validLengths = [12, 13, 14, 15, 16]
        if (!validLengths.includes(aesICVlen)) {
            throw new Error(
                'AES-GCM ICV length must be one of: 12, 13, 14, 15, or 16',
            )
        }
        this.aesICVlen = new Integer({ value: aesICVlen })
    }

    /**
     * Creates a GCMParameters instance from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns A new GCMParameters instance
     */
    static fromAsn1(asn1: Asn1BaseBlock): GCMParameters {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('GCMParameters must be a SEQUENCE')
        }

        const sequenceValue = asn1.valueBlock.value
        if (sequenceValue.length < 1 || sequenceValue.length > 2) {
            throw new Asn1ParseError(
                'GCMParameters sequence must have 1 or 2 elements',
            )
        }

        const aesNonce = (sequenceValue[0] as asn1js.OctetString).valueBlock
            .valueHexView

        let aesICVlen: number | undefined
        if (sequenceValue.length > 1) {
            if (!(sequenceValue[1] instanceof asn1js.Integer)) {
                throw new Asn1ParseError('aes-ICVlen must be an INTEGER')
            }
            aesICVlen = sequenceValue[1].valueBlock.valueDec
        }

        return new GCMParameters({ aesNonce, aesICVlen })
    }

    /**
     * Converts to ASN.1 structure
     *
     * @returns The ASN.1 representation of the GCMParameters
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.aesNonce.toAsn1(), this.aesICVlen.toAsn1()],
        })
    }
}
