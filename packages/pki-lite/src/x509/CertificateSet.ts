import { CertificateChoices } from './CertificateChoices.js'
import { Asn1BaseBlock, asn1js, PkiSet } from '../core/PkiBase.js'
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
    static fromAsn1(asn1: Asn1BaseBlock): CertificateSet {
        if (!(asn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Set for CertificateSet',
            )
        }

        const certificates = asn1.valueBlock.value.map((certAsn1) =>
            CertificateChoices.fromAsn1(certAsn1),
        )

        return new CertificateSet(...certificates)
    }
}
