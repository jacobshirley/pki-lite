import { Asn1Node, Choice, TagClass, UniversalTag } from '../core/PkiBase.js'
import { Certificate } from './Certificate.js'
import { ExtendedCertificate } from './legacy/ExtendedCertificate.js'
import { AttributeCertificateV1 } from './attribute-certs/AttributeCertificateV1.js'
import { AttributeCertificate } from './attribute-certs/AttributeCertificate.js'
import { OtherCertificateFormat } from './legacy/OtherCertificateFormat.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a certificate choice structure used in PKCS#7/CMS.
 *
 * @asn
 * ```asn
 * CertificateChoices ::= CHOICE {
 *      certificate Certificate,
 *      extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
 *      v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
 *      v2AttrCert [2] IMPLICIT AttributeCertificate,
 *      other [3] IMPLICIT OtherCertificateFormat
 * }
 *
 * AttributeCertificateV2 ::= AttributeCertificate
 *
 * OtherCertificateFormat ::= SEQUENCE {
 *      otherCertFormat OBJECT IDENTIFIER,
 *      otherCert ANY DEFINED BY otherCertFormat
 * }
 * ```
 */
export type CertificateChoices =
    | Certificate
    | ExtendedCertificate
    | AttributeCertificateV1
    | AttributeCertificate
    | OtherCertificateFormat

export const CertificateChoices = Choice('CertificateChoices', {
    Certificate,
    ExtendedCertificate,
    AttributeCertificateV1,
    AttributeCertificate,
    OtherCertificateFormat,
    fromAsn1: (value: Asn1Node): CertificateChoices => {
        // Check the tag class and tag number to determine the type
        const tagClass = value.tagClass
        const tagNumber = value.tag

        // Standard X.509 Certificate is a universal SEQUENCE
        if (value.is(UniversalTag.Sequence)) {
            return Certificate.fromAsn1(value)
        }

        if (tagClass !== TagClass.Context) {
            throw new Asn1ParseError(
                `Unknown CertificateChoices tag class: ${tagClass}`,
            )
        }
        // Context-specific tag class indicates an alternative choice; each is an
        // IMPLICIT tag over a SEQUENCE type, so read it back as a SEQUENCE
        const sequence = value.retag(UniversalTag.Sequence)
        switch (tagNumber) {
            case 0:
                // [0] IMPLICIT ExtendedCertificate (obsolete)
                return ExtendedCertificate.fromAsn1(sequence)
            case 1:
                // [1] IMPLICIT AttributeCertificateV1 (obsolete)
                return AttributeCertificateV1.fromAsn1(sequence)
            case 2:
                // [2] IMPLICIT AttributeCertificate (AttributeCertificateV2)
                return AttributeCertificate.fromAsn1(sequence)
            case 3:
                // [3] IMPLICIT OtherCertificateFormat
                return OtherCertificateFormat.fromAsn1(sequence)
            default:
                throw new Asn1ParseError(
                    `Unknown CertificateChoices tag number: ${tagNumber}`,
                )
        }
    },
})
