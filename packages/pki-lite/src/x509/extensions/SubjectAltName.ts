import { Asn1Node, UniversalTag } from '../../core/PkiBase.js'
import { GeneralName, GeneralNames } from '../GeneralName.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the Subject Alternative Name extension defined in RFC 5280.
 *
 * The Subject Alternative Name extension allows identities to be bound to the
 * subject of the certificate. These identities may be included in addition to
 * or in place of the identity in the subject field of the certificate.
 *
 * @asn
 * ```asn
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * ```
 */
export class SubjectAltName extends GeneralNames {
    static fromAsn1(asn1: Asn1Node): SubjectAltName {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for SubjectAltName',
            )
        }

        const generalNames: GeneralName[] = asn1.children.map(
            GeneralName.fromAsn1,
        )
        return new SubjectAltName(...generalNames)
    }
}
