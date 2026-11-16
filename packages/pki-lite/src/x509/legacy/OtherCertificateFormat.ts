import { Any } from '../../asn1/Any.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import {
    Asn1Any,
    Asn1Node,
    der,
    ObjectIdentifierString,
    PkiBase,
    UniversalTag,
} from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an OtherCertificateFormat structure.
 *
 * @asn
 * ```asn
 * OtherCertificateFormat ::= SEQUENCE {
 *      otherCertFormat OBJECT IDENTIFIER,
 *      otherCert ANY DEFINED BY otherCertFormat
 * }
 * ```
 */
export class OtherCertificateFormat extends PkiBase<OtherCertificateFormat> {
    otherCertFormat: ObjectIdentifier
    otherCert: Any

    /**
     * Creates a new OtherCertificateFormat instance.
     *
     * @param otherCertFormat The format identifier OID
     * @param otherCert The certificate in the specified format
     */
    constructor(options: {
        otherCertFormat: ObjectIdentifierString
        otherCert: Asn1Any
    }) {
        super()
        const { otherCertFormat, otherCert } = options
        this.otherCertFormat = new ObjectIdentifier({ value: otherCertFormat })
        this.otherCert = new Any({ derBytes: otherCert })
    }

    /**
     * Converts the OtherCertificateFormat to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        return der.sequence([
            this.otherCertFormat.toAsn1(),
            this.otherCert.toAsn1(),
        ])
    }

    /**
     * Creates an OtherCertificateFormat from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The OtherCertificateFormat
     */
    static fromAsn1(asn1: Asn1Node): OtherCertificateFormat {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.children.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements',
            )
        }

        const [formatAsn1, certAsn1] = asn1.children

        if (!formatAsn1.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
            )
        }

        // Extract the OID string
        const otherCertFormat = der.readOid(formatAsn1)
        const otherCert = new Any({ derBytes: certAsn1 })

        return new OtherCertificateFormat({
            otherCertFormat,
            otherCert,
        })
    }
}
