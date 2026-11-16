import { Asn1Node, Choice, UniversalTag } from '../core/PkiBase.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'
import { implicitSequence, isContextTag } from '../core/tagging.js'

/**
 * Represents a single revocation information choice.
 *
 * @asn
 * ```asn
 * RevocationInfoChoice ::= CHOICE {
 *      crl CertificateList,
 *      other [1] IMPLICIT OtherRevocationInfoFormat
 * }
 *
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *      otherRevInfoFormat OBJECT IDENTIFIER,
 *      otherRevInfo ANY DEFINED BY otherRevInfoFormat
 * }
 * ```
 */
export type RevocationInfoChoice = CertificateList | OtherRevocationInfoFormat

export const RevocationInfoChoice = Choice('RevocationInfoChoice', {
    CertificateList,
    OtherRevocationInfoFormat,
    fromAsn1: (value: Asn1Node): RevocationInfoChoice => {
        if (value.isContext(1)) {
            // other [1] IMPLICIT OtherRevocationInfoFormat
            return OtherRevocationInfoFormat.fromAsn1(implicitSequence(value))
        } else {
            return CertificateList.fromAsn1(value)
        }
    },
})
