import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'

export interface ReasonFlagsOptions {
    unused?: boolean
    keyCompromise?: boolean
    cACompromise?: boolean
    affiliationChanged?: boolean
    superseded?: boolean
    cessationOfOperation?: boolean
    certificateHold?: boolean
    privilegeWithdrawn?: boolean
    aACompromise?: boolean
}

/**
 * Represents X.509 ReasonFlags extension
 *
 * @asn
 * ```asn
 * ReasonFlags ::= BIT STRING {
 *     unused                  (0),
 *     keyCompromise           (1),
 *     cACompromise            (2),
 *     affiliationChanged      (3),
 *     superseded              (4),
 *     cessationOfOperation    (5),
 *     certificateHold         (6),
 *     privilegeWithdrawn      (7),
 *     aACompromise            (8)
 * }
 */
export class ReasonFlags extends PkiBase<ReasonFlags> {
    unused: boolean
    keyCompromise: boolean
    cACompromise: boolean
    affiliationChanged: boolean
    superseded: boolean
    cessationOfOperation: boolean
    certificateHold: boolean
    privilegeWithdrawn: boolean
    aACompromise: boolean

    constructor(options?: ReasonFlagsOptions) {
        super()
        this.unused = options?.unused ?? false
        this.keyCompromise = options?.keyCompromise ?? false
        this.cACompromise = options?.cACompromise ?? false
        this.affiliationChanged = options?.affiliationChanged ?? false
        this.superseded = options?.superseded ?? false
        this.cessationOfOperation = options?.cessationOfOperation ?? false
        this.certificateHold = options?.certificateHold ?? false
        this.privilegeWithdrawn = options?.privilegeWithdrawn ?? false
        this.aACompromise = options?.aACompromise ?? false
    }

    toAsn1(): Asn1BaseBlock {
        const bits = [
            this.unused,
            this.keyCompromise,
            this.cACompromise,
            this.affiliationChanged,
            this.superseded,
            this.cessationOfOperation,
            this.certificateHold,
            this.privilegeWithdrawn,
            this.aACompromise,
        ]
        // Always encode all 9 bits (ReasonFlags flags)
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

    static fromAsn1(asn1: Asn1BaseBlock): ReasonFlags {
        if (!(asn1 instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'ReasonFlags: Expected BitString for ReasonFlags',
            )
        }

        const bytes = new Uint8Array(asn1.valueBlock.valueHexView)
        if (bytes.length === 0) {
            throw new Asn1ParseError('ReasonFlags: BitString has no content')
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
        // Pad bits array to length 9 (all ReasonFlags bits)
        while (bits.length < 9) {
            bits.push(0)
        }
        return new ReasonFlags({
            unused: bits[0] === 1,
            keyCompromise: bits[1] === 1,
            cACompromise: bits[2] === 1,
            affiliationChanged: bits[3] === 1,
            superseded: bits[4] === 1,
            cessationOfOperation: bits[5] === 1,
            certificateHold: bits[6] === 1,
            privilegeWithdrawn: bits[7] === 1,
            aACompromise: bits[8] === 1,
        })
    }
}
