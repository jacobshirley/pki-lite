import { Asn1BaseBlock, Choice } from '../core/PkiBase.js'
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
    fromAsn1: (value: Asn1BaseBlock): CertificateChoices => {
        // Check the tag class and tag number to determine the type
        const tagClass = value.idBlock.tagClass
        const tagNumber = value.idBlock.tagNumber

        // Standard X.509 Certificate has universal tag class and sequence tag number (16)
        if (tagClass === 1 && tagNumber === 16) {
            return Certificate.fromAsn1(value)
        }

        if (tagClass !== 3) {
            throw new Asn1ParseError(
                `Unknown CertificateChoices tag class: ${tagClass}`,
            )
        }
        // Context-specific tag class indicates an alternative choice
        switch (tagNumber) {
            case 0:
                // [0] IMPLICIT ExtendedCertificate (obsolete)
                return ExtendedCertificate.fromAsn1(value)
            case 1:
                // [1] IMPLICIT AttributeCertificateV1 (obsolete)
                return AttributeCertificateV1.fromAsn1(value)
            case 2:
                // [2] IMPLICIT AttributeCertificate (AttributeCertificateV2)
                return AttributeCertificate.fromAsn1(value)
            case 3:
                // [3] IMPLICIT OtherCertificateFormat
                return OtherCertificateFormat.fromAsn1(value)
            default:
                throw new Asn1ParseError(
                    `Unknown CertificateChoices tag number: ${tagNumber}`,
                )
        }
    },
})
