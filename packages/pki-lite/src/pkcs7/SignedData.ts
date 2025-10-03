import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    PkiSet,
    derToAsn1,
} from '../core/PkiBase.js'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'
import { SignerInfo } from './SignerInfo.js'
import {
    DigestAlgorithmIdentifier,
    AlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { RevocationInfoChoice } from '../revocation/RevocationInfoChoice.js'
import { CertificateChoices } from '../x509/CertificateChoices.js'
import { SignedDataBuilder } from '../core/builders/SignedDataBuilder.js'
import { ContentInfo } from './ContentInfo.js'
import { OIDs } from '../core/OIDs.js'
import { CertificateSet } from '../x509/CertificateSet.js'
import { RevocationInfoChoices } from '../revocation/RevocationInfoChoices.js'
import { CMSVersion } from './CMSVersion.js'
import { Certificate } from '../x509/Certificate.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { OtherRevocationInfoFormat } from '../revocation/OtherRevocationInfoFormat.js'
import { CertificateList } from '../x509/CertificateList.js'
import {
    CertificateValidationOptions,
    CertificateValidator,
} from '../core/CertificateValidator.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a set of digest algorithm identifiers.
 *
 * This class is used to group multiple digest algorithm identifiers.
 *
 * @asn
 * ```asn
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * ```
 */
class DigestAlgorithmIdentifiers extends PkiSet<DigestAlgorithmIdentifier> {
    constructor(...items: AlgorithmIdentifier[]) {
        super(
            ...items.map(
                (item) =>
                    new DigestAlgorithmIdentifier({
                        algorithm: item.algorithm.value,
                        parameters: item.parameters,
                    }),
            ),
        )
    }
}

/**
 * Represents a set of signer information.
 *
 * This class is used to group multiple signer information structures.
 *
 * @asn
 * ```asn
 * SignerInfos ::= SET OF SignerInfo
 * ```
 */
class SignerInfos extends PkiSet<SignerInfo> {}

/**
 * Represents a CMS/PKCS#7 SignedData structure.
 *
 * SignedData is used to digitally sign content. It can contain the signed content
 * (attached signature) or just the signature information (detached signature).
 * Multiple signers can sign the same content, and certificates and CRLs can be
 * included for signature verification.
 *
 * @asn
 * ```asn
 * SignedData ::= SEQUENCE {
 *      version CMSVersion,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      encapContentInfo EncapsulatedContentInfo,
 *      certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *      signerInfos SignerInfos
 * }
 * CMSVersion ::= INTEGER
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * SignerInfos ::= SET OF SignerInfo
 * CertificateSet ::= SET OF Certificate
 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
 * ```
 *
 * @example
 * ```typescript
 * // Create signed data with builder
 * const signedData = await SignedData.builder()
 *    .setContent(new Uint8Array([0x01, 0x02, 0x03, 0x04]))
 *    .addSigner({
 *        certificate: signerCert,
 *        privateKey: signerPrivateKey
 *    })
 *    .addCertificate(signerCert)
 *    .build()
 *
 * // Verify signatures
 * const isValid = await signedData.verify({
 *     data: originalData,
 * })
 * ```
 */
export class SignedData extends PkiBase<SignedData> {
    /**
     * Reference to DigestAlgorithmIdentifier class.
     */
    static DigestAlgorithmIdentifier = DigestAlgorithmIdentifier

    /**
     * Reference to DigestAlgorithmIdentifiers class.
     */
    static DigestAlgorithmIdentifiers = DigestAlgorithmIdentifiers

    /**
     * Reference to SignerInfos class.
     */
    static SignerInfos = SignerInfos

    /**
     * Reference to CertificateSet class.
     */
    static CertificateSet = CertificateSet

    /**
     * Reference to RevocationInfoChoices class.
     */
    static RevocationInfoChoices = RevocationInfoChoices

    /**
     * Version of the CMS structure.
     */
    version: CMSVersion

    /**
     * Set of digest algorithms used by signers.
     */
    digestAlgorithms: DigestAlgorithmIdentifiers

    /**
     * Information about the encapsulated content being signed.
     */
    encapContentInfo: EncapsulatedContentInfo

    /**
     * Optional set of certificates for signature verification.
     */
    certificates?: CertificateSet

    /**
     * Optional set of certificate revocation information.
     */
    crls?: RevocationInfoChoices
    signerInfos: SignerInfos

    constructor(options: {
        version: CMSVersion
        digestAlgorithms: AlgorithmIdentifier[]
        encapContentInfo: EncapsulatedContentInfo
        signerInfos: SignerInfo[]
        certificates?: CertificateChoices[]
        crls?: RevocationInfoChoice[]
    }) {
        super()
        const {
            version,
            digestAlgorithms,
            encapContentInfo,
            signerInfos,
            certificates,
            crls,
        } = options

        this.version = version
        this.digestAlgorithms = new DigestAlgorithmIdentifiers(
            ...digestAlgorithms,
        )
        this.encapContentInfo = encapContentInfo
        this.signerInfos = new SignerInfos(...signerInfos)
        this.certificates = certificates?.length
            ? new CertificateSet(...certificates)
            : undefined
        this.crls = crls?.length
            ? new RevocationInfoChoices(...crls)
            : undefined
    }

    /**
     * Converts the SignedData to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values = [
            new asn1js.Integer({ value: this.version }),
            this.digestAlgorithms.toAsn1(),
            this.encapContentInfo.toAsn1(),
        ]

        // Certificates [0] IMPLICIT (optional)
        if (this.certificates && this.certificates.length > 0) {
            const certificatesAsn1 = this.certificates.toAsn1()
            certificatesAsn1.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
            certificatesAsn1.idBlock.tagNumber = 0 // [0]

            values.push(certificatesAsn1)
        }

        // CRLs [1] IMPLICIT (optional)
        if (this.crls && this.crls.length > 0) {
            const crlsAsn1 = this.crls.toAsn1()

            crlsAsn1.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
            crlsAsn1.idBlock.tagNumber = 1 // [1]

            values.push(crlsAsn1)
        }

        values.push(this.signerInfos.toAsn1())

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a SignedData from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The SignedData object
     */
    static fromAsn1(asn1: Asn1BaseBlock): SignedData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for SignedData: expected SEQUENCE',
            )
        }

        // Extract the components from the ASN.1 structure
        if (asn1.valueBlock.value.length < 4) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for SignedData: insufficient elements',
            )
        }

        // Extract the version
        const versionAsn1 = asn1.valueBlock.value[0]
        if (!(versionAsn1 instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for SignedData: expected INTEGER for version',
            )
        }

        const version = versionAsn1.valueBlock.valueDec

        // Extract digest algorithms
        const digestAlgorithmsAsn1 = asn1.valueBlock.value[1]
        if (!(digestAlgorithmsAsn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for SignedData: expected SET for digestAlgorithms',
            )
        }

        const digestAlgorithms: DigestAlgorithmIdentifier[] = []
        for (const digestAlgorithmAsn1 of digestAlgorithmsAsn1.valueBlock
            .value) {
            digestAlgorithms.push(
                DigestAlgorithmIdentifier.fromAsn1(digestAlgorithmAsn1),
            )
        }

        // Extract encapsulated content info
        const encapContentInfoAsn1 = asn1.valueBlock.value[2]
        const encapContentInfo =
            EncapsulatedContentInfo.fromAsn1(encapContentInfoAsn1)

        // Process remaining optional elements
        let currentIndex = 3
        let certificates: CertificateChoices[] | undefined
        let crls: RevocationInfoChoice[] | undefined

        // Check for certificates [0] IMPLICIT
        if (
            currentIndex < asn1.valueBlock.value.length &&
            asn1.valueBlock.value[currentIndex] instanceof asn1js.Constructed &&
            (asn1.valueBlock.value[currentIndex] as asn1js.Constructed).idBlock
                .tagNumber === 0
        ) {
            const certificatesAsn1 = asn1.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            certificates = []

            for (const certAsn1 of certificatesAsn1.valueBlock.value) {
                certificates.push(CertificateChoices.fromAsn1(certAsn1))
            }

            currentIndex++
        }

        // Check for CRLs [1] IMPLICIT
        if (
            currentIndex < asn1.valueBlock.value.length &&
            asn1.valueBlock.value[currentIndex] instanceof asn1js.Constructed &&
            (asn1.valueBlock.value[currentIndex] as asn1js.Constructed).idBlock
                .tagNumber === 1
        ) {
            const crlsAsn1 = asn1.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            crls = []

            for (const crlAsn1 of crlsAsn1.valueBlock.value) {
                crls.push(RevocationInfoChoice.fromAsn1(crlAsn1))
            }

            currentIndex++
        }

        // Extract signer infos
        if (currentIndex >= asn1.valueBlock.value.length) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for SignedData: missing signerInfos',
            )
        }

        const signerInfosAsn1 = asn1.valueBlock.value[currentIndex]
        if (!(signerInfosAsn1 instanceof asn1js.Set)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for SignedData: expected SET for signerInfos',
            )
        }

        const signerInfos: SignerInfo[] = []
        for (const signerInfoAsn1 of signerInfosAsn1.valueBlock.value) {
            signerInfos.push(SignerInfo.fromAsn1(signerInfoAsn1))
        }

        // Create and return the SignedData object
        return new SignedData({
            version,
            digestAlgorithms,
            encapContentInfo,
            signerInfos,
            certificates,
            crls,
        })
    }

    /**
     * Creates a SignedData from a DER-encoded byte array.
     *
     * @param der The DER-encoded SignedData
     * @returns The SignedData object
     */
    static fromDer(der: Uint8Array<ArrayBuffer>): SignedData {
        return SignedData.fromAsn1(derToAsn1(der))
    }

    /**
     * Creates a SignedData from a ContentInfo structure or DER bytes.
     * @param cms The ContentInfo or DER bytes
     * @returns The SignedData object
     */
    static fromCms(cms: ContentInfo | Uint8Array<ArrayBuffer>): SignedData {
        if (cms instanceof Uint8Array) {
            cms = ContentInfo.fromDer(cms)
        }

        if (cms.contentType.toString() !== OIDs.PKCS7.SIGNED_DATA) {
            throw new Asn1ParseError(
                `Invalid content type: expected ${OIDs.PKCS7.SIGNED_DATA}, got ${cms.contentType}`,
            )
        }

        if (!cms.content) {
            throw new Error('ContentInfo has no content')
        }

        return cms.content.parseAs(SignedData)
    }

    /**
     * Creates a builder for constructing a SignedData object.
     * @returns A new SignedDataBuilder instance
     */
    static builder(): SignedDataBuilder {
        return new SignedDataBuilder()
    }

    /**
     * Returns a ContentInfo object with this SignedData as content
     * @returns ContentInfo object
     */
    toCms(): ContentInfo {
        return new ContentInfo({
            contentType: OIDs.PKCS7.SIGNED_DATA,
            content: this,
        })
    }

    /**
     * Verifies the signatures in the SignedData object.
     *
     * @param options Verification options
     * @param options.data Optional original data for detached signatures
     * @param options.certificateValidation Certificate validation options or true for default validation
     * @returns
     */
    async verify(options: {
        data?: Uint8Array<ArrayBuffer>
        certificateValidation?: CertificateValidationOptions | true
    }): Promise<
        | {
              valid: true
              signerInfo: SignerInfo
          }
        | {
              valid: false
              reasons: string[]
          }
    > {
        const reasons: string[] = []

        if (this.signerInfos.length === 0) {
            return {
                valid: false,
                reasons: ['No signerInfos present in SignedData'],
            }
        }

        let validSignerInfo: SignerInfo | null = null

        for (const signerInfo of this.signerInfos) {
            const cert = this.findCertificateForSignerInfo(signerInfo)
            if (!cert) {
                reasons.push('No matching certificate found for signerInfo')
                continue
            }

            const result = await signerInfo.verify({
                data: options.data,
                publicKeyInfo: cert.tbsCertificate.subjectPublicKeyInfo,
            })

            if (!result.valid) {
                reasons.push(...result.reasons)
            } else {
                validSignerInfo = signerInfo
                break
            }
        }

        if (!validSignerInfo) {
            return { valid: false, reasons }
        }

        if (options.certificateValidation) {
            const certificateValidator = new CertificateValidator()
            const validationOptions: CertificateValidationOptions =
                options.certificateValidation === true
                    ? {
                          validateChain: true,
                          checkCRL: true,
                          checkOCSP: true,
                          otherCertificates: this.certificates?.filter(
                              (c): c is Certificate => c instanceof Certificate,
                          ),
                          checkSignature: true,
                          enforceCAConstraints: true,
                          validateNameConstraints: true,
                      }
                    : options.certificateValidation

            const validationResult = await certificateValidator.validate(
                this.findCertificateForSignerInfo(validSignerInfo)!,
                validationOptions,
            )

            if (validationResult.status !== 'VALID') {
                return {
                    valid: false,
                    reasons: [
                        `Certificate validation failed: ${validationResult.status}`,
                    ],
                }
            }
        }

        return { valid: true, signerInfo: validSignerInfo }
    }

    private findCertificateForSignerInfo(
        signerInfo: SignerInfo,
    ): Certificate | undefined {
        if (!this.certificates) {
            throw new Error('No certificates available in SignedData')
        }

        for (const cert of this.certificates) {
            if (cert instanceof Certificate) {
                if (cert && signerInfo.sid.matchesCertificate(cert)) {
                    return cert
                }
            }
        }
        return undefined
    }

    /**
     * Adds an OCSPResponse to the SignedData's CRLs.
     *
     * @param OCSP The OCSPResponse to add
     */
    addOcsp(OCSP: OCSPResponse): void {
        this.crls = this.crls ?? new RevocationInfoChoices()
        this.crls.push(
            new OtherRevocationInfoFormat({
                otherRevInfoFormat: OIDs.OTHER_REV_INFO.OCSP,
                otherRevInfo: OCSP,
            }),
        )
    }

    /**
     * Adds a CRL to the SignedData's CRLs.
     *
     * @param crl The CertificateList (CRL) to add
     */
    addCrl(crl: CertificateList): void {
        this.crls = this.crls ?? new RevocationInfoChoices()
        this.crls.push(crl)
    }
}
