import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
import { KeyIdentifier } from './KeyIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a SubjectKeyIdentifier structure as defined in RFC 5652.
 * @asn
 * ```asn
 * SubjectKeyIdentifier ::= OCTET STRING
 * ```
 */
type SubjectKeyIdentifier = OctetString
const SubjectKeyIdentifier = OctetString

/**
 * Represents a KeyAgreeRecipientIdentifier structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * RecipientKeyIdentifier ::= SEQUENCE {
 *   subjectKeyIdentifier SubjectKeyIdentifier,
 *   date GeneralizedTime OPTIONAL,
 *   other OtherKeyAttribute OPTIONAL
 * }
 * ```
 */
export class RecipientKeyIdentifier extends PkiBase<RecipientKeyIdentifier> {
    subjectKeyIdentifier: SubjectKeyIdentifier
    date?: Date
    other?: OtherKeyAttribute

    constructor(options: {
        subjectKeyIdentifier: KeyIdentifier
        date?: Date
        other?: OtherKeyAttribute
    }) {
        super()

        const { subjectKeyIdentifier, date, other } = options

        this.subjectKeyIdentifier = subjectKeyIdentifier
        this.date = date
        this.other = other
    }

    toAsn1(): Asn1Node {
        const values = [this.subjectKeyIdentifier.toAsn1()]

        if (this.date) {
            values.push(der.generalizedTime(this.date))
        }

        if (this.other) {
            values.push(this.other.toAsn1())
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): RecipientKeyIdentifier {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for RecipientKeyIdentifier',
            )
        }

        const values = asn1.children
        if (values.length < 1 || values.length > 3) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-3 elements, got ${values.length}`,
            )
        }

        let currentIndex = 0
        const subjectKeyIdentifier = KeyIdentifier.fromAsn1(
            values[currentIndex],
        )
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

        return new RecipientKeyIdentifier({
            subjectKeyIdentifier,
            date,
            other,
        })
    }
}
