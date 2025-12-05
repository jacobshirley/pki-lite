import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { Attribute } from '../Attribute.js'
import { Extension } from '../Extension.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents the holder of an attribute certificate.
 * According to RFC 5755, the holder is defined as:
 *
 * @asn
 * ```asn
 * Holder ::= SEQUENCE {
 *     baseCertificateID   [0] IssuerSerial OPTIONAL,
 *     entityName          [1] GeneralNames OPTIONAL,
 *     objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
 * }
 *
 * IssuerSerial ::= SEQUENCE {
 *     issuer         GeneralNames,
 *     serial         CertificateSerialNumber,
 *     issuerUID      UniqueIdentifier OPTIONAL
 * }
 *
 * ObjectDigestInfo ::= SEQUENCE {
 *     digestedObjectType  ENUMERATED {
 *         publicKey            (0),
 *         publicKeyCert        (1),
 *         otherObjectTypes     (2) },
 *     otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
 *     digestAlgorithm     AlgorithmIdentifier,
 *     objectDigest        BIT STRING
 * }
 * ```
 *
 * This implementation provides a simplified representation.
 */
export class Holder extends PkiBase<Holder> {
    // Simplified implementation for the holder
    holderValue: Uint8Array<ArrayBuffer>

    /**
     * Creates a new Holder instance.
     *
     * @param options Configuration options for the holder
     * @param options.holderValue The binary representation of the holder
     */
    constructor(options: { holderValue: Uint8Array<ArrayBuffer> }) {
        super()
        this.holderValue = options.holderValue
    }

    /**
     * Converts the Holder to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [new asn1js.OctetString({ valueHex: this.holderValue })],
        })
    }

    /**
     * Creates a Holder from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The Holder
     */
    static fromAsn1(asn1: Asn1BaseBlock): Holder {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // This is a simplified implementation
        const holderValue = new Uint8Array(asn1.toBER(false))
        return new Holder({ holderValue })
    }
}

/**
 * Represents the issuer of an attribute certificate.
 * According to RFC 5755, the issuer is defined as:
 *
 * @asn
 * ```asn
 * AttCertIssuer ::= [0] EXPLICIT SEQUENCE {
 *     issuerName              GeneralNames OPTIONAL,
 *     baseCertificateID  [0]  IssuerSerial OPTIONAL,
 *     objectDigestInfo   [1]  ObjectDigestInfo OPTIONAL
 * }
 * ```
 *
 * This implementation provides a simplified representation.
 */
export class AttCertIssuer extends PkiBase<AttCertIssuer> {
    // Simplified implementation for the issuer
    issuerValue: Uint8Array<ArrayBuffer>

    /**
     * Creates a new AttCertIssuer instance.
     *
     * @param options Configuration options for the issuer
     * @param options.issuerValue The binary representation of the issuer
     */
    constructor(options: { issuerValue: Uint8Array<ArrayBuffer> }) {
        super()
        this.issuerValue = options.issuerValue
    }

    /**
     * Converts the AttCertIssuer to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [new asn1js.OctetString({ valueHex: this.issuerValue })],
        })
    }

    /**
     * Creates an AttCertIssuer from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttCertIssuer
     */
    static fromAsn1(asn1: Asn1BaseBlock): AttCertIssuer {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // This is a simplified implementation
        const issuerValue = new Uint8Array(asn1.toBER(false))
        return new AttCertIssuer({ issuerValue })
    }
}

/**
 * Represents the information in an attribute certificate.
 * According to RFC 5755, the attribute certificate info is defined as:
 *
 * @asn
 * ```asn
 * AttributeCertificateInfo ::= SEQUENCE {
 *     version              AttCertVersion -- version is v2,
 *     holder               Holder,
 *     issuer               AttCertIssuer,
 *     signature            AlgorithmIdentifier,
 *     serialNumber         CertificateSerialNumber,
 *     attrCertValidityPeriod   AttCertValidityPeriod,
 *     attributes           SEQUENCE OF Attribute,
 *     issuerUniqueID       UniqueIdentifier OPTIONAL,
 *     extensions           Extensions OPTIONAL
 * }
 *
 * AttCertVersion ::= INTEGER { v2(1) }
 *
 * AttCertValidityPeriod ::= SEQUENCE {
 *     notBeforeTime  GeneralizedTime,
 *     notAfterTime   GeneralizedTime
 * }
 * ```
 */
export class AttributeCertificateInfo extends PkiBase<AttributeCertificateInfo> {
    version: number
    holder: Holder
    issuer: AttCertIssuer
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
     * Creates a new AttributeCertificateInfo instance.
     *
     * @param version The version of the attribute certificate (should be 1 for v2)
     * @param holder The holder of the certificate
     * @param issuer The issuer of the certificate
     * @param signature The algorithm used to sign the certificate
     * @param serialNumber The serial number of the certificate
     * @param validityPeriod The validity period of the certificate
     * @param attributes The attributes certified by this certificate
     * @param issuerUniqueID Optional unique identifier of the issuer
     * @param extensions Optional extensions
     */
    constructor(options: {
        version: number
        holder: Holder
        issuer: AttCertIssuer
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
        this.version = options.version
        this.holder = options.holder
        this.issuer = options.issuer
        this.signature = options.signature
        this.serialNumber = options.serialNumber
        this.validityPeriod = options.validityPeriod
        this.attributes = options.attributes
        this.issuerUniqueID = options.issuerUniqueID
        this.extensions = options.extensions
    }

    /**
     * Converts the AttributeCertificateInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const value: asn1js.BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            this.holder.toAsn1(),
            this.issuer.toAsn1(),
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
     * Creates an AttributeCertificateInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The AttributeCertificateInfo
     */
    static fromAsn1(asn1: Asn1BaseBlock): AttributeCertificateInfo {
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

        // Extract holder
        if (!(values[1] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for holder',
            )
        }
        const holder = Holder.fromAsn1(values[1])

        // Extract issuer
        if (!(values[2] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for issuer',
            )
        }
        const issuer = AttCertIssuer.fromAsn1(values[2])

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
            notBefore: validityValues[0].toDate() ?? new Date(),
            notAfter: validityValues[1].toDate() ?? new Date(),
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
        let issuerUniqueID: Uint8Array<ArrayBuffer> | undefined
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

        return new AttributeCertificateInfo({
            version,
            holder,
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
