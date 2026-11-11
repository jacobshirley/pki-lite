import { CertificateChoices } from './CertificateChoices.js'
import { Asn1Node, PkiSet, UniversalTag } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of certificates.
 *
 * This class is used to group multiple certificate structures.
 *
 * @asn
 * ```asn
 * CertificateSet ::= SET OF CertificateChoices
 * ```
 */
export class CertificateSet extends PkiSet<CertificateChoices> {
    static fromAsn1(asn1: Asn1Node): CertificateSet {
        if (!asn1.is(UniversalTag.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for CertificateSet',
            )
        }

        const certificates = asn1.children.map((certAsn1) =>
            CertificateChoices.fromAsn1(certAsn1),
        )

        return new CertificateSet(...certificates)
    }
}
