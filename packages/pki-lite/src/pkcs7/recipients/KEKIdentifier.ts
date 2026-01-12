import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a KEKIdentifier structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * KEKIdentifier ::= SEQUENCE {
 *   keyIdentifier OCTET STRING,
 *   date GeneralizedTime OPTIONAL,
 *   other OtherKeyAttribute OPTIONAL
 * }
 * ```
 */
export class KEKIdentifier extends PkiBase<KEKIdentifier> {
    keyIdentifier: Uint8Array<ArrayBuffer>
    date?: Date
    other?: OtherKeyAttribute

    constructor(options: {
        keyIdentifier: Uint8Array<ArrayBuffer>
        date?: Date
        other?: OtherKeyAttribute
    }) {
        super()

        const { keyIdentifier, date, other } = options

        this.keyIdentifier = keyIdentifier
        this.date = date
        this.other = other
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.OctetString({ valueHex: this.keyIdentifier }),
        ]

        if (this.date) {
            values.push(new asn1js.GeneralizedTime({ valueDate: this.date }))
        }

        if (this.other) {
            values.push(this.other.toAsn1())
        }

        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): KEKIdentifier {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KEKIdentifier',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 3) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-3 elements, got ${values.length}`,
            )
        }

        if (!(values[0] instanceof asn1js.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for keyIdentifier',
            )
        }

        let currentIndex = 0
        const keyIdentifier = new Uint8Array(values[0].valueBlock.valueHexView)
        currentIndex++

        // Date handling is skipped for simplicity
        let date: Date | undefined = undefined
        if (values[currentIndex] instanceof asn1js.GeneralizedTime) {
            date = new Date(
                (
                    values[currentIndex] as asn1js.GeneralizedTime
                ).valueBlock.value,
            )
            currentIndex++
        }

        let other: OtherKeyAttribute | undefined = undefined
        if (values[currentIndex] instanceof asn1js.Sequence) {
            other = OtherKeyAttribute.fromAsn1(values[currentIndex])
            currentIndex++
        }

        return new KEKIdentifier({
            keyIdentifier,
            date,
            other,
        })
    }
}
