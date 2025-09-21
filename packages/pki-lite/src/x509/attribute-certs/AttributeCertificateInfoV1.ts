import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
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
    subject: Uint8Array // Simplified representation for the subject choice
    issuer: Uint8Array // Simplified representation for GeneralNames
    signature: AlgorithmIdentifier
    serialNumber: Uint8Array
    validityPeriod: {
        notBefore: Date
        notAfter: Date
    }
    attributes: Attribute[]
    issuerUniqueID?: Uint8Array
    extensions?: Extension[]

    /**
     * Creates a new AttributeCertificateInfoV1 instance.
     *
     * @param options The options object containing the certificate information
     */
    constructor(options: {
        version: number
        subject: Uint8Array
        issuer: Uint8Array
        signature: AlgorithmIdentifier
        serialNumber: Uint8Array
        validityPeriod: {
            notBefore: Date
            notAfter: Date
        }
        attributes: Attribute[]
        issuerUniqueID?: Uint8Array
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
    toAsn1(): Asn1BaseBlock {
        const value: asn1js.BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            // Simplified subject representation
            new asn1js.OctetString({ valueHex: this.subject }),
            // Simplified issuer representation
            new asn1js.OctetString({ valueHex: this.issuer }),
            this.signature.toAsn1(),
            new asn1js.Integer({ valueHex: this.serialNumber }),
            new asn1js.Sequence({
                value: [
                    new asn1js.GeneralizedTime({
                        valueDate: this.validityPeriod.notBefore,
                    }),
                    new asn1js.GeneralizedTime({
                        valueDate: this.validityPeriod.notAfter,
                    }),
                ],
            }),
            new asn1js.Sequence({
                value: this.attributes.map((attr) => attr.toAsn1()),
            }),
        ]

        if (this.issuerUniqueID) {
            value.push(new asn1js.BitString({ valueHex: this.issuerUniqueID }))
        }

        if (this.extensions && this.extensions.length > 0) {
            value.push(
                new asn1js.Sequence({
                    value: this.extensions.map((ext) => ext.toAsn1()),
                }),
            )
        }

        return new asn1js.Sequence({ value })
    }

    /**
     * Creates an AttributeCertificateInfoV1 from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttributeCertificateInfoV1
     */
    static fromAsn1(asn1: Asn1BaseBlock): AttributeCertificateInfoV1 {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // For this obsolete structure, we use a simplified implementation
        // that just captures the binary representation

        // Define a type for the valueBlock structure we need to access
        interface ValueBlock {
            value: asn1js.BaseBlock[]
        }

        const values = (asn1.valueBlock as unknown as ValueBlock).value
        if (values.length < 7) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected at least 7 elements',
            )
        }

        // Extract version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for version',
            )
        }
        const version = values[0].valueBlock.valueDec

        // Extract subject (simplified)
        const subject = new Uint8Array(values[1].toBER(false))

        // Extract issuer (simplified)
        const issuer = new Uint8Array(values[2].toBER(false))

        // Extract signature algorithm
        if (!(values[3] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signature',
            )
        }
        const signature = AlgorithmIdentifier.fromAsn1(values[3])

        // Extract serial number
        if (!(values[4] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected INTEGER for serialNumber',
            )
        }
        const serialNumber = new Uint8Array(values[4].valueBlock.valueHexView)

        // Extract validity period
        if (!(values[5] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for validityPeriod',
            )
        }

        const validityValues = (values[5].valueBlock as unknown as ValueBlock)
            .value
        if (validityValues.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements in validityPeriod',
            )
        }

        if (
            !(validityValues[0] instanceof asn1js.GeneralizedTime) ||
            !(validityValues[1] instanceof asn1js.GeneralizedTime)
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected GeneralizedTime for validity dates',
            )
        }

        const validityPeriod = {
            notBefore: validityValues[0].toDate(),
            notAfter: validityValues[1].toDate(),
        }

        // Extract attributes
        if (!(values[6] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for attributes',
            )
        }

        const attributesValues = (values[6].valueBlock as unknown as ValueBlock)
            .value
        const attributes = attributesValues.map((attr) =>
            Attribute.fromAsn1(attr),
        )

        // Extract optional issuerUniqueID if present
        let issuerUniqueID: Uint8Array | undefined
        let extensions: Extension[] | undefined

        if (values.length > 7) {
            if (values[7] instanceof asn1js.BitString) {
                issuerUniqueID = new Uint8Array(
                    values[7].valueBlock.valueHexView,
                )
            }

            // Extract optional extensions if present
            if (values.length > 8 && values[8] instanceof asn1js.Sequence) {
                const extensionsValues = (
                    values[8].valueBlock as unknown as ValueBlock
                ).value
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
