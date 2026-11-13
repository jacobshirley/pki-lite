import { GeneralizedTime } from '../../asn1/GeneralizedTime.js'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [der.octetString(this.keyIdentifier)]

        if (this.date) {
            values.push(new GeneralizedTime({ time: this.date }).toAsn1())
        }

        if (this.other) {
            values.push(this.other.toAsn1())
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): KEKIdentifier {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for KEKIdentifier',
            )
        }

        const values = asn1.children
        if (values.length < 1 || values.length > 3) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-3 elements, got ${values.length}`,
            )
        }

        if (!values[0]?.is(UniversalTag.OctetString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OctetString for keyIdentifier',
            )
        }

        let currentIndex = 0
        const keyIdentifier = values[0].bytes()
        currentIndex++

        // Date handling is skipped for simplicity
        let date: Date | undefined = undefined
        if (values[currentIndex]?.is(UniversalTag.GeneralizedTime)) {
            date = der.readTime(values[currentIndex])
            currentIndex++
        }

        let other: OtherKeyAttribute | undefined = undefined
        if (values[currentIndex]?.is(UniversalTag.Sequence)) {
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
