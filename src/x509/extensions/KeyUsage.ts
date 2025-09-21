import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'

export interface KeyUsageOptions {
    digitalSignature?: boolean
    nonRepudiation?: boolean
    keyEncipherment?: boolean
    dataEncipherment?: boolean
    keyAgreement?: boolean
    keyCertSign?: boolean
    cRLSign?: boolean
    encipherOnly?: boolean
    decipherOnly?: boolean
}

/**
 * Represents X.509 KeyUsage extension
 *
 * @asn
 * ```asn
 * KeyUsage ::= BIT STRING {
 *    digitalSignature        (0),
 *    nonRepudiation          (1), -- recent editions of X.509 have
 *                                 -- renamed this bit to contentCommitment
 *    keyEncipherment         (2),
 *    dataEncipherment        (3),
 *    keyAgreement            (4),
 *    keyCertSign             (5),
 *    cRLSign                 (6),
 *    encipherOnly            (7),
 *    decipherOnly            (8)
 * }
 */
export class KeyUsage extends PkiBase<KeyUsage> {
    digitalSignature: boolean
    nonRepudiation: boolean
    keyEncipherment: boolean
    dataEncipherment: boolean
    keyAgreement: boolean
    keyCertSign: boolean
    cRLSign: boolean
    encipherOnly: boolean
    decipherOnly: boolean

    constructor(options?: KeyUsageOptions) {
        super()
        this.digitalSignature = options?.digitalSignature ?? false
        this.nonRepudiation = options?.nonRepudiation ?? false
        this.keyEncipherment = options?.keyEncipherment ?? false
        this.dataEncipherment = options?.dataEncipherment ?? false
        this.keyAgreement = options?.keyAgreement ?? false
        this.keyCertSign = options?.keyCertSign ?? false
        this.cRLSign = options?.cRLSign ?? false
        this.encipherOnly = options?.encipherOnly ?? false
        this.decipherOnly = options?.decipherOnly ?? false
    }

    toAsn1(): Asn1BaseBlock {
        const bits = [
            this.digitalSignature,
            this.nonRepudiation,
            this.keyEncipherment,
            this.dataEncipherment,
            this.keyAgreement,
            this.keyCertSign,
            this.cRLSign,
            this.encipherOnly,
            this.decipherOnly,
        ]
        // Always encode all 9 bits (KeyUsage flags)
        const unusedBits = (8 - ((bits.length - 1) % 8)) % 8
        const byteLength = Math.ceil(bits.length / 8)
        const bytes = new Uint8Array(byteLength + 1) // +1 for unused bits byte
        bytes[0] = unusedBits
        for (let i = 0; i < bits.length; i++) {
            if (bits[i] === true) {
                const byteIndex = Math.floor(i / 8) + 1 // +1 for unused bits byte
                const bitIndex = 7 - (i % 8)
                bytes[byteIndex] |= 1 << bitIndex
            }
        }
        return new asn1js.BitString({ valueHex: bytes.buffer })
    }

    static fromAsn1(asn1: Asn1BaseBlock): KeyUsage {
        if (!(asn1 instanceof asn1js.BitString)) {
            throw new Asn1ParseError('Expected BitString for KeyUsage')
        }

        const bytes = new Uint8Array(asn1.valueBlock.valueHexView)
        if (bytes.length === 0) {
            throw new Asn1ParseError('BitString has no content')
        }

        const unusedBits = bytes[0]
        const totalBits = (bytes.length - 1) * 8 - unusedBits

        const bits: (0 | 1)[] = []
        for (let i = 0; i < totalBits; i++) {
            const byteIndex = Math.floor(i / 8) + 1 // +1 for unused bits byte
            const bitIndex = 7 - (i % 8)
            const bit = (bytes[byteIndex] >> bitIndex) & 1
            bits.push(bit as 0 | 1)
        }
        // Pad bits array to length 9 (all KeyUsage bits)
        while (bits.length < 9) {
            bits.push(0)
        }
        return new KeyUsage({
            digitalSignature: bits[0] === 1,
            nonRepudiation: bits[1] === 1,
            keyEncipherment: bits[2] === 1,
            dataEncipherment: bits[3] === 1,
            keyAgreement: bits[4] === 1,
            keyCertSign: bits[5] === 1,
            cRLSign: bits[6] === 1,
            encipherOnly: bits[7] === 1,
            decipherOnly: bits[8] === 1,
        })
    }
}
