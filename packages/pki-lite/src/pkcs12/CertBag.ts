import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    ObjectIdentifierString,
    derToAsn1,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a CertBag structure in a PKCS#12 file.
 *
 * A CertBag is used to store certificates within PKCS#12 files. It specifies
 * the certificate type (certId) and contains the certificate data (certValue).
 * The most common certificate type is X.509 certificates, but other formats
 * can also be stored.
 *
 * @asn
 * ```asn
 * CertBag ::= SEQUENCE {
 *   certId    BAG-TYPE,
 *   certValue [0] EXPLICIT ANY DEFINED BY certId
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Create a certificate bag for an X.509 certificate
 * const certBag = new CertBag({
 *     certId: OIDs.x509Certificate,
 *     certValue: certificate.toDer()
 * })
 *
 * // Extract certificate from bag
 * if (certBag.certId.is(OIDs.x509Certificate)) {
 *     const certBytes = certBag.certValue.toAsn1().valueBlock.valueHex
 *     const certificate = Certificate.fromDer(new Uint8Array(certBytes))
 * }
 *
 * // Create from existing certificate
 * const bagFromCert = CertBag.fromCertificate(certificate)
 * ```
 */
export class CertBag extends PkiBase<CertBag> {
    /**
     * Object identifier specifying the certificate type.
     * Common value is OIDs.x509Certificate for X.509 certificates.
     */
    certId: ObjectIdentifier

    /**
     * The certificate data, format determined by certId.
     */
    certValue: Any

    /**
     * Creates a new CertBag instance.
     *
     * @param options Configuration object
     * @param options.certId Object identifier for the certificate type
     * @param options.certValue The certificate data
     */
    constructor(options: {
        certId: ObjectIdentifierString
        certValue: Asn1Any
    }) {
        super()
        this.certId = new ObjectIdentifier({ value: options.certId })
        this.certValue = new Any({ derBytes: options.certValue })
    }

    /**
     * Converts this CertBag to its ASN.1 representation.
     *
     * @returns The ASN.1 SEQUENCE structure
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.certId.toAsn1(),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 }, // [0] EXPLICIT
                    value: [this.certValue.toAsn1()],
                }),
            ],
        })
    }

    /**
     * Creates a CertBag from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 SEQUENCE to parse
     * @returns A new CertBag instance
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     */
    static fromAsn1(asn1: Asn1BaseBlock): CertBag {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('CertBag: expected SEQUENCE')
        }
        const [id, val] = asn1.valueBlock.value
        if (!(id instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'CertBag: certId must be OBJECT IDENTIFIER',
            )
        }
        if (
            !(val instanceof asn1js.Constructed) ||
            val.idBlock.tagClass !== 3 ||
            val.idBlock.tagNumber !== 0 ||
            val.valueBlock.value.length !== 1
        ) {
            throw new Asn1ParseError(
                'CertBag: certValue must be [0] EXPLICIT with single element',
            )
        }
        return new CertBag({
            certId: id.valueBlock.toString(),
            certValue: new Any({ derBytes: val.valueBlock.value[0] }),
        })
    }

    static fromDer(der: Uint8Array): CertBag {
        return CertBag.fromAsn1(derToAsn1(der))
    }
}
