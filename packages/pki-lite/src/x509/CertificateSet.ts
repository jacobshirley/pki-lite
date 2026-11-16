import { CertificateChoices } from './CertificateChoices.js'
import { ExtendedCertificate } from './legacy/ExtendedCertificate.js'
import { AttributeCertificateV1 } from './attribute-certs/AttributeCertificateV1.js'
import { AttributeCertificate } from './attribute-certs/AttributeCertificate.js'
import { OtherCertificateFormat } from './legacy/OtherCertificateFormat.js'
import { implicitTag } from '../core/tagging.js'
import { Asn1Node, der, PkiSet, UniversalTag } from '../core/PkiBase.js'
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
    /**
     * Encodes the set, tagging each alternative other than a plain Certificate with
     * its CertificateChoices tag (all IMPLICIT): extendedCertificate [0], v1AttrCert
     * [1], v2AttrCert [2] and other [3].
     */
    toAsn1(): Asn1Node {
        return der.set(
            [...this].map((choice) => {
                const asn1 = choice.toAsn1()
                if (choice instanceof ExtendedCertificate)
                    return implicitTag(asn1, 0)
                if (choice instanceof AttributeCertificateV1)
                    return implicitTag(asn1, 1)
                if (choice instanceof AttributeCertificate)
                    return implicitTag(asn1, 2)
                if (choice instanceof OtherCertificateFormat)
                    return implicitTag(asn1, 3)
                return asn1
            }),
        )
    }

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
