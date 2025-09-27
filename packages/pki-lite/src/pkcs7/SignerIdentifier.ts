import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'
import { Asn1BaseBlock, asn1js, Choice } from '../core/PkiBase.js'
import { SubjectKeyIdentifier } from '../keys/SubjectKeyIdentifier.js'

/**
 * Represents a CMS SignerIdentifier structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * SignerIdentifier ::= CHOICE {
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      subjectKeyIdentifier [0] SubjectKeyIdentifier
 * }
 * ```
 */
export type SignerIdentifier = IssuerAndSerialNumber | SubjectKeyIdentifier
export const SignerIdentifier = Choice('SignerIdentifier', {
    IssuerAndSerialNumber,
    SubjectKeyIdentifier,
    fromAsn1(asn1: Asn1BaseBlock): SignerIdentifier {
        if (asn1.idBlock.tagNumber === 0) {
            return SubjectKeyIdentifier.fromAsn1(asn1)
        }
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
})
