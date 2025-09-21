import { OctetString } from '../asn1/OctetString.js'
import { OIDs } from '../core/OIDs.js'
import { Asn1BaseBlock, asn1js, bytesToHexString } from '../core/PkiBase.js'
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
    static fromAsn1(asn1: Asn1BaseBlock): SubjectKeyIdentifier {
        if (asn1 instanceof asn1js.OctetString) {
            return new SubjectKeyIdentifier({
                bytes: asn1.valueBlock.valueHexView,
            })
        }

        throw new Asn1ParseError(
            'Invalid ASN.1 structure for SubjectKeyIdentifier',
        )
    }

    static fromDer(der: Uint8Array): SubjectKeyIdentifier {
        return SubjectKeyIdentifier.fromAsn1(asn1js.fromBER(der).result)
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
