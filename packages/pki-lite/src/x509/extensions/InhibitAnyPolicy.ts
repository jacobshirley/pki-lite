import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the X.509 inhibitAnyPolicy extension (RFC 5280 4.2.1.14): the number of
 * additional certificates that may appear in the path before `anyPolicy` is no longer
 * considered a match.
 *
 * @asn
 * ```asn
 * InhibitAnyPolicy ::= SkipCerts
 * SkipCerts ::= INTEGER (0..MAX)
 * ```
 */
export class InhibitAnyPolicy extends PkiBase<InhibitAnyPolicy> {
    skipCerts: number

    constructor(options: { skipCerts: number }) {
        super()
        this.skipCerts = options.skipCerts
    }

    toAsn1(): Asn1Node {
        return der.integer(this.skipCerts)
    }

    static fromAsn1(asn1: Asn1Node): InhibitAnyPolicy {
        if (!asn1.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for InhibitAnyPolicy: expected INTEGER',
            )
        }
        return new InhibitAnyPolicy({ skipCerts: der.readNumber(asn1) })
    }
}
