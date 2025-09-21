import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'
import { Integer } from '../asn1/Integer.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents CCM Parameters as defined in RFC 5084.
 *
 * @asn
 * ```asn
 * CCMParameters ::= SEQUENCE {
 *   aes-nonce         OCTET STRING (SIZE(7..13)),
 *   aes-ICVlen        AES-CCM-ICVlen DEFAULT 12
 * }
 *
 * AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
 * ```
 */
export class CCMParameters extends PkiBase<CCMParameters> {
    aesNonce: OctetString
    aesICVlen: Integer

    /**
     * Creates a new instance of CCMParameters
     */
    constructor(options: {
        aesNonce: OctetString | Uint8Array
        aesICVlen?: number
    }) {
        super()
        const { aesNonce, aesICVlen = 12 } = options

        let nonceOctetString: OctetString
        if (aesNonce instanceof Uint8Array) {
            nonceOctetString = new OctetString({ bytes: aesNonce })
        } else {
            nonceOctetString = aesNonce
        }

        // Validate nonce size
        if (
            nonceOctetString.bytes.length < 7 ||
            nonceOctetString.bytes.length > 13
        ) {
            throw new Error('AES-CCM nonce must be between 7 and 13 octets')
        }

        this.aesNonce = nonceOctetString

        const validLengths = [4, 6, 8, 10, 12, 14, 16]
        if (!validLengths.includes(aesICVlen)) {
            throw new Error(
                'AES-CCM ICV length must be one of: 4, 6, 8, 10, 12, 14, or 16',
            )
        }
        this.aesICVlen = new Integer({ value: aesICVlen })
    }

    /**
     * Creates a CCMParameters instance from an ASN.1 structure
     *
     * @param asn1 The ASN.1 structure
     * @returns A new CCMParameters instance
     */
    static fromAsn1(asn1: Asn1BaseBlock): CCMParameters {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('CCMParameters must be a SEQUENCE')
        }

        const sequenceValue = asn1.valueBlock.value
        if (sequenceValue.length < 1 || sequenceValue.length > 2) {
            throw new Asn1ParseError(
                'CCMParameters sequence must have 1 or 2 elements',
            )
        }

        const aesNonce = OctetString.fromAsn1(sequenceValue[0])

        let aesICVlen: number | undefined
        if (sequenceValue.length > 1) {
            if (!(sequenceValue[1] instanceof asn1js.Integer)) {
                throw new Asn1ParseError('aes-ICVlen must be an INTEGER')
            }
            aesICVlen = sequenceValue[1].valueBlock.valueDec
        }

        return new CCMParameters({ aesNonce, aesICVlen })
    }

    /**
     * Converts to ASN.1 structure
     *
     * @returns The ASN.1 representation of the CCMParameters
     */
    toAsn1(): Asn1BaseBlock {
        const sequence = new asn1js.Sequence()

        // Add nonce
        sequence.valueBlock.value.push(this.aesNonce.toAsn1())
        sequence.valueBlock.value.push(this.aesICVlen.toAsn1())

        return sequence
    }
}
