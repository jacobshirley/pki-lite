import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Name } from '../x509/Name.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { Integer } from '../asn1/Integer.js'
import { CertificateChoices } from '../x509/CertificateChoices.js'
import { Certificate } from '../x509/Certificate.js'
import { AttributeCertificate } from '../x509/attribute-certs/AttributeCertificate.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an IssuerAndSerialNumber structure used in PKCS#7.
 *
 * @asn
 * ```asn
 * IssuerAndSerialNumber ::= SEQUENCE {
 *      issuer Name,
 *      serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER
 * ```
 */
export class IssuerAndSerialNumber extends PkiBase<IssuerAndSerialNumber> {
    issuer: Name
    serialNumber: Integer

    constructor(options: {
        issuer: Name
        serialNumber: Uint8Array | number | string | Integer
    }) {
        super()
        const { issuer, serialNumber } = options

        this.issuer = issuer
        this.serialNumber = new Integer({ value: serialNumber })
    }

    /**
     * Converts the IssuerAndSerialNumber to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.issuer.toAsn1(), this.serialNumber.toAsn1()],
        })
    }

    /**
     * Creates an IssuerAndSerialNumber from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns An IssuerAndSerialNumber
     */
    static fromAsn1(asn1: Asn1BaseBlock): IssuerAndSerialNumber {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE but got ' +
                    asn1.constructor.name,
            )
        }

        if (asn1.valueBlock.value.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements',
            )
        }

        const issuerAsn1 = asn1.valueBlock.value[0]
        const serialNumberAsn1 = asn1.valueBlock.value[1]

        if (!(issuerAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: issuer must be a SEQUENCE',
            )
        }

        const issuer = RDNSequence.fromAsn1(issuerAsn1)
        const serialNumber = Integer.fromAsn1(serialNumberAsn1)

        return new IssuerAndSerialNumber({ issuer, serialNumber })
    }

    matchesCertificate(cert: CertificateChoices): boolean {
        if (cert instanceof Certificate) {
            return (
                cert.tbsCertificate.issuer.equals(this.issuer) &&
                cert.tbsCertificate.serialNumber.equals(this.serialNumber)
            )
        } else {
            throw new Error('Unsupported certificate choice for matching')
        }
    }

    toHumanString(): string {
        return `${this.issuer.toHumanString()}, SN=${this.serialNumber.toHexString()}`
    }
}
