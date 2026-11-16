import { OctetString } from '../asn1/OctetString.js'
import { OIDs } from '../core/OIDs.js'
import {
    Asn1Node,
    bytesToHexString,
    derToAsn1,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { Certificate } from '../x509/Certificate.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a CMS SubjectKeyIdentifier structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * SubjectKeyIdentifier ::= OCTET STRING
 * ```
 */
export class SubjectKeyIdentifier extends OctetString {
    static fromAsn1(asn1: Asn1Node): SubjectKeyIdentifier {
        if (asn1.is(UniversalTag.OctetString)) {
            return new SubjectKeyIdentifier({
                bytes: asn1.bytes(),
            })
        }

        // `subjectKeyIdentifier [0] SubjectKeyIdentifier` in CMS (SignerIdentifier,
        // RecipientIdentifier, ...) is IMPLICIT, so DER parsing yields a primitive
        // context-specific value rather than a universal OCTET STRING.
        if (!asn1.constructed && asn1.tagClass === TagClass.Context) {
            return new SubjectKeyIdentifier({
                bytes: asn1.bytes(),
            })
        }

        throw new Asn1ParseError(
            'Invalid ASN.1 structure for SubjectKeyIdentifier',
        )
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): SubjectKeyIdentifier {
        return SubjectKeyIdentifier.fromAsn1(derToAsn1(der))
    }

    matchesCertificate(cert: Certificate): boolean {
        const ext = cert.tbsCertificate.getExtensionByOid(
            OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER,
        )

        if (!ext) {
            return false
        }

        const extValue = ext.extnValue.parseAs(SubjectKeyIdentifier)

        return extValue.equals(this)
    }

    toHumanString(): string {
        return `SKI=${bytesToHexString(this.bytes)}`
    }
}
