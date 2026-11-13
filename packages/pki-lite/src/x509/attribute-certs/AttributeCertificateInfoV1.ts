import { GeneralizedTime } from '../../asn1/GeneralizedTime.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Attribute } from '../Attribute.js'
import { Extension } from '../Extension.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the information in an attribute certificate v1 (obsolete).
 * This is based on the v2 structure but with version set to v1(0).
 *
 * @asn
 * ```asn
 * AttributeCertificateInfoV1 ::= SEQUENCE {
 *     version              AttCertVersionV1 DEFAULT v1,
 *     subject              CHOICE {
 *         baseCertificateID   [0] IssuerSerial,
 *         subjectName         [1] GeneralNames
 *     },
 *     issuer               GeneralNames,
 *     signature            AlgorithmIdentifier,
 *     serialNumber         CertificateSerialNumber,
 *     attCertValidityPeriod   AttCertValidityPeriod,
 *     attributes           SEQUENCE OF Attribute,
 *     issuerUniqueID       UniqueIdentifier OPTIONAL,
 *     extensions           Extensions OPTIONAL
 * }
 *
 * AttCertVersionV1 ::= INTEGER { v1(0) }
 * ```
 */
export class AttributeCertificateInfoV1 extends PkiBase<AttributeCertificateInfoV1> {
    version: number
    subject: Uint8Array<ArrayBuffer> // Simplified representation for the subject choice
    issuer: Uint8Array<ArrayBuffer> // Simplified representation for GeneralNames
    signature: AlgorithmIdentifier
    serialNumber: Uint8Array<ArrayBuffer>
    validityPeriod: {
        notBefore: Date
        notAfter: Date
    }
    attributes: Attribute[]
    issuerUniqueID?: Uint8Array<ArrayBuffer>
    extensions?: Extension[]

    /**
     * Creates a new AttributeCertificateInfoV1 instance.
     *
     * @param options The options object containing the certificate information
     */
    constructor(options: {
        version: number
        subject: Uint8Array<ArrayBuffer>
        issuer: Uint8Array<ArrayBuffer>
        signature: AlgorithmIdentifier
        serialNumber: Uint8Array<ArrayBuffer>
        validityPeriod: {
            notBefore: Date
            notAfter: Date
        }
        attributes: Attribute[]
        issuerUniqueID?: Uint8Array<ArrayBuffer>
        extensions?: Extension[]
    }) {
        super()
        const {
            version,
            subject,
            issuer,
            signature,
            serialNumber,
            validityPeriod,
            attributes,
            issuerUniqueID,
            extensions,
        } = options
        this.version = version
        this.subject = subject
        this.issuer = issuer
        this.signature = signature
        this.serialNumber = serialNumber
        this.validityPeriod = validityPeriod
        this.attributes = attributes
        this.issuerUniqueID = issuerUniqueID
        this.extensions = extensions
    }

    /**
     * Converts the AttributeCertificateInfoV1 to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        const value: Asn1Node[] = [
            der.integer(this.version),
            // Simplified subject representation
            der.octetString(this.subject),
            // Simplified issuer representation
            der.octetString(this.issuer),
            this.signature.toAsn1(),
            der.primitive(UniversalTag.Integer, this.serialNumber),
            der.sequence([
                new GeneralizedTime({
                    time: this.validityPeriod.notBefore,
                }).toAsn1(),
                new GeneralizedTime({
                    time: this.validityPeriod.notAfter,
                }).toAsn1(),
            ]),
            der.sequence(this.attributes.map((attr) => attr.toAsn1())),
        ]

        if (this.issuerUniqueID) {
            value.push(der.bitString(this.issuerUniqueID))
        }

        if (this.extensions && this.extensions.length > 0) {
            value.push(der.sequence(this.extensions.map((ext) => ext.toAsn1())))
        }

        return der.sequence(value)
    }

    /**
     * Creates an AttributeCertificateInfoV1 from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttributeCertificateInfoV1
     */
    static fromAsn1(asn1: Asn1Node): AttributeCertificateInfoV1 {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // For this obsolete structure, we use a simplified implementation
        // that just captures the binary representation

        const values = asn1.children
        if (values.length < 7) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 7 elements',
            )
        }

        // Extract version
        if (!values[0]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for version',
            )
        }
        const version = der.readNumber(values[0])

        // Extract subject (simplified)
        const subject = values[1].encode()

        // Extract issuer (simplified)
        const issuer = values[2].encode()

        // Extract signature algorithm
        if (!values[3]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signature',
            )
        }
        const signature = AlgorithmIdentifier.fromAsn1(values[3])

        // Extract serial number
        if (!values[4]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for serialNumber',
            )
        }
        const serialNumber = values[4].bytes()

        // Extract validity period
        if (!values[5]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for validityPeriod',
            )
        }

        const validityValues = values[5].children
        if (validityValues.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements in validityPeriod',
            )
        }

        if (
            !validityValues[0]?.is(UniversalTag.GeneralizedTime) ||
            !validityValues[1]?.is(UniversalTag.GeneralizedTime)
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected GeneralizedTime for validity dates',
            )
        }

        const validityPeriod = {
            notBefore: der.readTime(validityValues[0]),
            notAfter: der.readTime(validityValues[1]),
        }

        // Extract attributes
        if (!values[6]?.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for attributes',
            )
        }

        const attributesValues = values[6].children
        const attributes = attributesValues.map((attr) =>
            Attribute.fromAsn1(attr),
        )

        // Extract optional issuerUniqueID if present
        let issuerUniqueID: Uint8Array<ArrayBuffer> | undefined
        let extensions: Extension[] | undefined

        if (values.length > 7) {
            if (values[7]?.is(UniversalTag.BitString)) {
                issuerUniqueID = der.readBitString(values[7]).bytes
            }

            // Extract optional extensions if present
            if (values.length > 8 && values[8]?.is(UniversalTag.Sequence)) {
                const extensionsValues = values[8].children
                extensions = extensionsValues.map((ext) =>
                    Extension.fromAsn1(ext),
                )
            }
        }

        return new AttributeCertificateInfoV1({
            version,
            subject,
            issuer,
            signature,
            serialNumber,
            validityPeriod,
            attributes,
            issuerUniqueID,
            extensions,
        })
    }
}
