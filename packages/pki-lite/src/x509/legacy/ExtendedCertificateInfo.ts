import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { Certificate } from '../Certificate.js'
import { Attribute } from '../Attribute.js'
import { CMSVersion } from '../../pkcs7/CMSVersion.js'
import { Attributes } from '../Attributes.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the ExtendedCertificateInfo structure used in the ExtendedCertificate.
 *
 * This structure is marked as obsolete in the ASN.1 definition but is included for
 * compatibility with legacy systems.
 *
 * @asn
 * ```asn
 * ExtendedCertificateInfo ::= SEQUENCE {
 *     version CMSVersion,
 *     certificate Certificate,
 *     attributes UnauthAttributes
 * }
 *
 * UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
 * ```
 */
export class ExtendedCertificateInfo extends PkiBase<ExtendedCertificateInfo> {
    version: CMSVersion
    certificate: Certificate
    attributes: Attributes

    /**
     * Creates a new ExtendedCertificateInfo instance.
     *
     * @param options The options object containing the certificate information
     */
    constructor(options: {
        version: number
        certificate: Certificate
        attributes: Attribute[]
    }) {
        super()
        const { version, certificate, attributes } = options
        this.version = version
        this.certificate = certificate
        this.attributes = attributes?.length
            ? new Attributes(...attributes)
            : new Attributes()
    }

    /**
     * Converts the ExtendedCertificateInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: this.version }),
                this.certificate.toAsn1(),
                new asn1js.Set({
                    value: this.attributes.map((attribute) =>
                        attribute.toAsn1(),
                    ),
                }),
            ],
        })
    }

    /**
     * Creates an ExtendedCertificateInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The ExtendedCertificateInfo
     */
    static fromAsn1(asn1: Asn1BaseBlock): ExtendedCertificateInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // Define a type for the valueBlock structure we need to access
        interface ValueBlock {
            value: asn1js.BaseBlock[]
        }

        const values = (asn1.valueBlock as unknown as ValueBlock).value
        if (values.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        // Extract version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for version',
            )
        }
        const version = values[0].valueBlock.valueDec

        // Extract certificate
        if (!(values[1] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for certificate',
            )
        }

        const certificate = Certificate.fromAsn1(values[1])
        const attributes = Attributes.fromAsn1(values[2])

        return new ExtendedCertificateInfo({ version, certificate, attributes })
    }
}
