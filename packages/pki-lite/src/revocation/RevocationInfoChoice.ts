import { Asn1BaseBlock, Choice } from '../core/PkiBase.js'
import { CertificateList } from '../x509/CertificateList.js'
import { OtherRevocationInfoFormat } from './OtherRevocationInfoFormat.js'

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
    fromAsn1: (value: Asn1BaseBlock): RevocationInfoChoice => {
        const tagNumber = value.idBlock.tagNumber
        if (tagNumber === 1) {
            return OtherRevocationInfoFormat.fromAsn1(value)
        } else {
            return CertificateList.fromAsn1(value)
        }
    },
})
