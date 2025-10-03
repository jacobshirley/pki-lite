import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import {
    AlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { Validity } from './Validity.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Extension } from './Extension.js'
import { Name } from './Name.js'
import { Integer } from '../asn1/Integer.js'
import { OIDs } from '../core/OIDs.js'
import { IssuerSerial } from './IssuerSerial.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the "To Be Signed" part of the certificate.
 *
 * @asn
 * ```asn
 * TBSCertificate  ::=  SEQUENCE  {
 *      version         [0]  EXPLICIT Version DEFAULT v1,
 *      serialNumber         CertificateSerialNumber,
 *      signature            AlgorithmIdentifier,
 *      issuer               Name,
 *      validity             Validity,
 *      subject              Name,
 *      subjectPublicKeyInfo SubjectPublicKeyInfo,
 *      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions      [3]  EXPLICIT Extensions OPTIONAL
 * }
 *
 * CertificateSerialNumber ::= INTEGER
 * ```
 */
export class TBSCertificate extends PkiBase<TBSCertificate> {
    version: number
    serialNumber: Integer
    signature: SignatureAlgorithmIdentifier
    issuer: Name
    validity: Validity
    subject: Name
    subjectPublicKeyInfo: SubjectPublicKeyInfo
    issuerUniqueID?: Uint8Array<ArrayBuffer>
    subjectUniqueID?: Uint8Array<ArrayBuffer>
    extensions?: Extension[]

    constructor(options: {
        version?: number
        serialNumber: Uint8Array | number | string
        signature: AlgorithmIdentifier
        issuer: Name
        validity: Validity
        subject: Name
        subjectPublicKeyInfo: SubjectPublicKeyInfo
        issuerUniqueID?: Uint8Array<ArrayBuffer>
        subjectUniqueID?: Uint8Array<ArrayBuffer>
        extensions?: Extension[]
    }) {
        super()
        this.version = options.version ?? 0 // Default to v1
        this.serialNumber = new Integer({ value: options.serialNumber })
        this.signature = new SignatureAlgorithmIdentifier(options.signature)
        this.issuer = options.issuer
        this.validity = options.validity
        this.subject = options.subject
        this.subjectPublicKeyInfo = options.subjectPublicKeyInfo
        this.issuerUniqueID = options.issuerUniqueID
        this.subjectUniqueID = options.subjectUniqueID
        this.extensions = options.extensions
    }

    /**
     * Converts the TBSCertificate to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const tbsValues = []

        // Version [0] EXPLICIT
        tbsValues.push(
            new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 0, // [0]
                },
                value: [new asn1js.Integer({ value: this.version })],
            }),
        )

        tbsValues.push(this.serialNumber.toAsn1())

        // Signature Algorithm
        tbsValues.push(this.signature.toAsn1())

        // Issuer
        tbsValues.push(this.issuer.toAsn1())

        // Validity
        tbsValues.push(this.validity.toAsn1())

        // Subject
        tbsValues.push(this.subject.toAsn1())

        // SubjectPublicKeyInfo
        tbsValues.push(this.subjectPublicKeyInfo.toAsn1())

        // Optional fields
        if (this.issuerUniqueID) {
            tbsValues.push(
                new asn1js.Primitive({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    valueHex: this.issuerUniqueID,
                }),
            )
        }

        if (this.subjectUniqueID) {
            tbsValues.push(
                new asn1js.Primitive({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 2, // [2]
                    },
                    valueHex: this.subjectUniqueID,
                }),
            )
        }

        // Extensions
        if (this.extensions && this.extensions.length > 0) {
            const extensionsArray = this.extensions.map((ext) => ext.toAsn1())

            tbsValues.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 3, // [3]
                    },
                    value: [
                        new asn1js.Sequence({
                            value: extensionsArray,
                        }),
                    ],
                }),
            )
        }

        return new asn1js.Sequence({ value: tbsValues })
    }

    /**
     * Creates a TBSCertificate from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The TBSCertificate
     */
    static fromAsn1(asn1: Asn1BaseBlock): TBSCertificate {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: TBSCertificate must be a SEQUENCE',
            )
        }

        const tbsSequenceValue = asn1.valueBlock.value

        // Start with basic defaults
        let version = 0 // default v1
        let currentIndex = 0

        // Check if first element is version tag [0]
        const firstElement = tbsSequenceValue[0]
        if (
            firstElement instanceof asn1js.Constructed &&
            firstElement.idBlock.tagClass === 3 &&
            firstElement.idBlock.tagNumber === 0
        ) {
            // Version is present as explicit tag [0]
            const versionInt = firstElement.valueBlock.value[0]
            if (!(versionInt instanceof asn1js.Integer)) {
                throw new Asn1ParseError(
                    'Invalid TBSCertificate: version must be an INTEGER',
                )
            }
            version = versionInt.valueBlock.valueDec
            currentIndex++
        }

        // Serial Number (required)
        const serialAsn1 = tbsSequenceValue[currentIndex]
        if (!(serialAsn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid TBSCertificate: serialNumber must be an INTEGER',
            )
        }
        const serialNumber = serialAsn1.valueBlock.valueHexView
        currentIndex++

        // Signature Algorithm (required)
        const signatureAsn1 = tbsSequenceValue[currentIndex]
        if (!(signatureAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid TBSCertificate: signature must be a SEQUENCE',
            )
        }
        const signature = AlgorithmIdentifier.fromAsn1(signatureAsn1)
        currentIndex++

        // Issuer (required)
        const issuerAsn1 = tbsSequenceValue[currentIndex]
        if (!(issuerAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid TBSCertificate: issuer must be a SEQUENCE',
            )
        }
        const issuer = Name.fromAsn1(issuerAsn1)
        currentIndex++

        // Validity (required)
        const validityAsn1 = tbsSequenceValue[currentIndex]
        if (!(validityAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid TBSCertificate: validity must be a SEQUENCE',
            )
        }
        const validity = Validity.fromAsn1(validityAsn1)
        currentIndex++

        // Subject (required)
        const subjectAsn1 = tbsSequenceValue[currentIndex]
        if (!(subjectAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid TBSCertificate: subject must be a SEQUENCE',
            )
        }
        const subject = Name.fromAsn1(subjectAsn1)
        currentIndex++

        // SubjectPublicKeyInfo (required)
        const spkiAsn1 = tbsSequenceValue[currentIndex]
        if (!(spkiAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid TBSCertificate: subjectPublicKeyInfo must be a SEQUENCE',
            )
        }
        const subjectPublicKeyInfo = SubjectPublicKeyInfo.fromAsn1(spkiAsn1)
        currentIndex++

        // Optional fields
        let issuerUniqueID: Uint8Array<ArrayBuffer> | undefined
        let subjectUniqueID: Uint8Array<ArrayBuffer> | undefined
        let extensions: Extension[] | undefined

        // Parse issuerUniqueID [1] IMPLICIT (optional)
        if (
            currentIndex < tbsSequenceValue.length &&
            tbsSequenceValue[currentIndex] instanceof asn1js.Primitive &&
            tbsSequenceValue[currentIndex].idBlock.tagClass === 3 && // CONTEXT-SPECIFIC
            tbsSequenceValue[currentIndex].idBlock.tagNumber === 1 // [1]
        ) {
            const issuerUniqueIDAsn1 = tbsSequenceValue[
                currentIndex
            ] as asn1js.BitString
            issuerUniqueID = new Uint8Array(
                issuerUniqueIDAsn1.valueBlock.valueHexView,
            )
            currentIndex++
        }

        // Parse subjectUniqueID [2] IMPLICIT (optional)
        if (
            currentIndex < tbsSequenceValue.length &&
            tbsSequenceValue[currentIndex] instanceof asn1js.Primitive &&
            tbsSequenceValue[currentIndex].idBlock.tagClass === 3 && // CONTEXT-SPECIFIC
            tbsSequenceValue[currentIndex].idBlock.tagNumber === 2 // [2]
        ) {
            const subjectUniqueIDAsn1 = tbsSequenceValue[
                currentIndex
            ] as asn1js.BitString
            subjectUniqueID = new Uint8Array(
                subjectUniqueIDAsn1.valueBlock.valueHexView,
            )
            currentIndex++
        }

        // Parse extensions [3] EXPLICIT (optional)
        if (
            currentIndex < tbsSequenceValue.length &&
            tbsSequenceValue[currentIndex] instanceof asn1js.Constructed &&
            tbsSequenceValue[currentIndex].idBlock.tagClass === 3 && // CONTEXT-SPECIFIC
            tbsSequenceValue[currentIndex].idBlock.tagNumber === 3 // [3]
        ) {
            const extensionsContainer = tbsSequenceValue[
                currentIndex
            ] as asn1js.Constructed
            if (extensionsContainer.valueBlock.value.length > 0) {
                const extensionsSeq = extensionsContainer.valueBlock.value[0]
                if (extensionsSeq instanceof asn1js.Sequence) {
                    extensions = extensionsSeq.valueBlock.value.map((ext) =>
                        Extension.fromAsn1(ext),
                    )
                }
            }
        }

        return new TBSCertificate({
            version,
            serialNumber,
            signature,
            issuer,
            validity,
            subject,
            subjectPublicKeyInfo,
            issuerUniqueID,
            subjectUniqueID,
            extensions,
        })
    }

    getExtensionByOid(oid: string): Extension | undefined {
        if (!this.extensions) return undefined
        return this.extensions.find((ext) => ext.extnID.value === oid)
    }

    getExtensionByName(
        name: keyof typeof OIDs.EXTENSION,
    ): Extension | undefined {
        const oid = OIDs.EXTENSION[name]
        if (!oid) return undefined
        return this.getExtensionByOid(oid)
    }

    getExtensionsByOid(oid: string): Extension[] {
        if (!this.extensions) return []
        return this.extensions.filter((ext) => ext.extnID.value === oid)
    }

    getExtensionsByName(name: keyof typeof OIDs.EXTENSION): Extension[] {
        const oid = OIDs.EXTENSION[name]
        if (!oid) return []
        return this.getExtensionsByOid(oid)
    }

    getIssuerSerial() {
        return new IssuerSerial({
            issuer: this.issuer,
            serialNumber: this.serialNumber,
        })
    }
}
