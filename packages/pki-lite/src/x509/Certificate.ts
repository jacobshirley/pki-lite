import {
    Asn1Any,
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    pemToDer,
    PkiBase,
} from '../core/PkiBase.js'
import {
    AlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { TBSCertificate } from './TBSCertificate.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    HashAlgorithm,
} from '../core/crypto/types.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { RDNSequence } from './RDNSequence.js'
import { Validity } from './Validity.js'
import { Extension } from './Extension.js'
import { OIDs } from '../core/OIDs.js'
import { CertificateList } from './CertificateList.js'
import { CRLDistributionPoints } from './extensions/CRLDistributionPoints.js'
import { GeneralName } from './GeneralName.js'
import { OCSPResponse } from '../ocsp/OCSPResponse.js'
import { AuthorityInfoAccess } from './extensions/AuthorityInfoAccess.js'
import { OCSPRequest } from '../ocsp/OCSPRequest.js'
import { BitString } from '../asn1/BitString.js'
import { IssuerSerial } from './IssuerSerial.js'
import { Name } from './Name.js'
import {
    CertificateValidationOptions,
    CertificateValidationResult,
    CertificateValidator,
} from '../core/CertificateValidator.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an X.509 certificate.
 *
 * @asn
 * ```asn
 * Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING
 * }
 * ```
 */
export class Certificate extends PkiBase<Certificate> {
    static TBSCertificate = TBSCertificate

    tbsCertificate: TBSCertificate
    signatureAlgorithm: SignatureAlgorithmIdentifier
    signatureValue: BitString

    constructor(options: {
        tbsCertificate: TBSCertificate
        signatureAlgorithm: AlgorithmIdentifier
        signatureValue: Uint8Array | BitString
    }) {
        super()
        const { tbsCertificate, signatureAlgorithm, signatureValue } = options
        this.tbsCertificate = tbsCertificate
        this.signatureAlgorithm = new SignatureAlgorithmIdentifier(
            signatureAlgorithm,
        )
        this.signatureValue = new BitString({ value: signatureValue })
    }

    /**
     * Converts the certificate to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        // Create the main Certificate sequence
        return new asn1js.Sequence({
            value: [
                this.tbsCertificate.toAsn1(),
                this.signatureAlgorithm.toAsn1(),
                this.signatureValue.toAsn1(),
            ],
        })
    }

    /**
     * Creates a Certificate from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The Certificate
     */
    static fromAsn1(asn1: Asn1BaseBlock): Certificate {
        // Type check for root sequence
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        // Extract the three main components
        const sequence = asn1
        if (!(sequence instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }
        const sequenceValue = sequence.valueBlock.value

        if (sequenceValue.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        const tbsCertificateAsn1 = sequenceValue[0]
        if (!(tbsCertificateAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: tbsCertificate must be a SEQUENCE',
            )
        }

        const signatureAlgorithmAsn1 = sequenceValue[1]
        if (!(signatureAlgorithmAsn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: signatureAlgorithm must be a SEQUENCE',
            )
        }

        const signatureValueAsn1 = sequenceValue[2]
        if (!(signatureValueAsn1 instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: signatureValue must be a BIT STRING',
            )
        }

        // Create TBSCertificate
        const tbsCertificate = TBSCertificate.fromAsn1(tbsCertificateAsn1)
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            signatureAlgorithmAsn1,
        )

        // Get signature value
        const signatureValue = new Uint8Array(
            signatureValueAsn1.valueBlock.valueHexView,
        )

        return new Certificate({
            tbsCertificate,
            signatureAlgorithm,
            signatureValue,
        })
    }

    static fromDer(der: Uint8Array): Certificate {
        return Certificate.fromAsn1(derToAsn1(der))
    }

    static fromPem(pem: string): Certificate {
        return Certificate.fromDer(pemToDer(pem, 'CERTIFICATE'))
    }

    async getHash(algorithm: HashAlgorithm = 'SHA-1'): Promise<Uint8Array> {
        return AlgorithmIdentifier.digestAlgorithm(algorithm).digest(
            this.tbsCertificate.toDer(),
        )
    }

    getIssuerSerial(): IssuerSerial {
        return this.tbsCertificate.getIssuerSerial()
    }

    static async createSelfSignedCertificate(options: {
        algorithm?: AsymmetricEncryptionAlgorithmParams
        subject: string | Name
        subjectPublicKeyInfo: SubjectPublicKeyInfo
        privateKeyInfo: PrivateKeyInfo
        validity: {
            notBefore: Date
            notAfter: Date
        }
        extensions?: Extension[]
    }): Promise<Certificate> {
        const {
            subject,
            subjectPublicKeyInfo,
            privateKeyInfo,
            validity,
            algorithm,
        } = options

        const encryptionAlg = AlgorithmIdentifier.signatureAlgorithm(
            algorithm ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: {
                    hash: 'SHA-256',
                },
            },
        )

        const tbs = new TBSCertificate({
            version: 2,
            serialNumber: new Uint8Array([1, 0, 0, 0]), // Example serial number
            signature: encryptionAlg,
            issuer: RDNSequence.parse(subject),
            validity: new Validity({
                notBefore: validity.notBefore,
                notAfter: validity.notAfter,
            }),
            subject: RDNSequence.parse(subject),
            subjectPublicKeyInfo,
            extensions: options.extensions,
        })

        const signatureValue = await encryptionAlg.sign(
            tbs.toDer(),
            privateKeyInfo,
        )

        return new Certificate({
            tbsCertificate: tbs,
            signatureAlgorithm: encryptionAlg,
            signatureValue,
        })
    }

    static async createCertificate(options: {
        algorithm?: AsymmetricEncryptionAlgorithmParams
        issuer: Certificate
        subject: string | Name
        subjectPublicKeyInfo: SubjectPublicKeyInfo
        privateKeyInfo: PrivateKeyInfo
        validity: {
            notBefore: Date
            notAfter: Date
        }
        serialNumber?: Uint8Array
        extensions?: Extension[]
    }): Promise<Certificate> {
        const {
            issuer,
            subject,
            subjectPublicKeyInfo,
            privateKeyInfo,
            validity,
            serialNumber,
            algorithm,
        } = options

        const encryptionAlg = AlgorithmIdentifier.signatureAlgorithm(
            algorithm ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: {
                    hash: 'SHA-256',
                },
            },
        )

        const tbs = new TBSCertificate({
            version: 2,
            serialNumber: serialNumber ?? new Uint8Array([1, 0, 0, 0]), // Example serial number
            signature: encryptionAlg,
            issuer:
                issuer instanceof Certificate
                    ? issuer.tbsCertificate.subject
                    : RDNSequence.parse(issuer),
            validity: new Validity({
                notBefore: validity.notBefore,
                notAfter: validity.notAfter,
            }),
            subject: RDNSequence.parse(subject),
            subjectPublicKeyInfo,
            extensions: options.extensions,
        })

        const signatureValue = await encryptionAlg.sign(
            tbs.toDer(),
            privateKeyInfo,
        )

        return new Certificate({
            tbsCertificate: tbs,
            signatureAlgorithm: encryptionAlg,
            signatureValue,
        })
    }

    getExtensionByOid(oid: string): Extension | undefined {
        return this.tbsCertificate.getExtensionByOid(oid)
    }

    getExtensionByName(
        name: keyof typeof OIDs.EXTENSION,
    ): Extension | undefined {
        return this.tbsCertificate.getExtensionByName(name)
    }

    getExtensionsByOid(oid: string): Extension[] {
        return this.tbsCertificate.getExtensionsByOid(oid)
    }

    getExtensionsByName(name: keyof typeof OIDs.EXTENSION): Extension[] {
        return this.tbsCertificate.getExtensionsByName(name)
    }

    getSubjectPublicKeyInfo(): SubjectPublicKeyInfo {
        return this.tbsCertificate.subjectPublicKeyInfo
    }

    async requestCrl(options?: {
        crlDistributionPointUrls?: string[]
    }): Promise<CertificateList | undefined> {
        const crlDp = this.getExtensionByName('CRL_DISTRIBUTION_POINTS')
        if (!crlDp) {
            return undefined
        }

        const crlDistributionPoints = crlDp.extnValue.parseAs(
            CRLDistributionPoints,
        )

        const urls = options?.crlDistributionPointUrls ?? []

        for (const dp of crlDistributionPoints) {
            if (!dp.distributionPoint) {
                continue
            }

            for (const name of dp.distributionPoint) {
                if (!(name instanceof GeneralName.uniformResourceIdentifier)) {
                    console.warn(
                        'Skipping non-URI GeneralName in CRLDistributionPoints. Type: ' +
                            name.pkiType,
                    )
                    continue
                }

                const uri = name.toString()
                urls.push(uri)
            }

            for (const uri of urls) {
                try {
                    const response = await fetch(uri)
                    if (!response.ok) {
                        console.warn(
                            `Failed to fetch CRL from ${uri}: ${response.status} ${response.statusText}`,
                        )
                        continue
                    }
                    const crlDer = new Uint8Array(await response.arrayBuffer())
                    return CertificateList.fromDer(crlDer)
                } catch (e) {
                    if (!(e instanceof Error)) {
                        throw e
                    }

                    console.warn(`Error fetching CRL from ${uri}:`, e.message)
                    continue
                }
            }
        }

        return undefined
    }

    async requestOcsp(options?: {
        issuerCertificate?: Certificate
        ocspResponderUrls?: string[]
        issuerCertificateUrls?: string[]
    }): Promise<OCSPResponse | undefined> {
        const issuerCertificate =
            options?.issuerCertificate ??
            (await this.requestIssuerCertificate(options))

        if (!issuerCertificate) {
            console.warn(
                'WARNING: No issuer certificate found. Cannot fetch OCSP. To hide this warning, set options.issuerCertificate.',
            )
            return undefined
        }

        const aiaExt = this.getExtensionByName('AUTHORITY_INFO_ACCESS')
        if (!aiaExt) {
            return undefined
        }

        const aia = aiaExt.extnValue.parseAs(AuthorityInfoAccess)
        const ocspDescriptions = aia.filter(
            (ad) => ad.accessMethod.value === OIDs.AUTHORITY_INFO_ACCESS.OCSP,
        )

        if (ocspDescriptions.length === 0) {
            return undefined
        }

        const urls = options?.ocspResponderUrls ?? []

        for (const ad of ocspDescriptions) {
            if (
                !(
                    ad.accessLocation instanceof
                    GeneralName.uniformResourceIdentifier
                )
            ) {
                console.warn(
                    'Skipping non-URI GeneralName in AuthorityInfoAccess. Type: ' +
                        ad.accessLocation.pkiType,
                )
                continue
            }

            const uri = ad.accessLocation.toString()
            urls.push(uri)
        }

        for (const uri of urls) {
            try {
                const ocspRequest = await OCSPRequest.forCertificate({
                    certificate: this,
                    issuerCertificate,
                })
                const response = await ocspRequest.request({ url: uri })
                return response
            } catch (e) {
                if (!(e instanceof Error)) {
                    throw e
                }

                console.warn(
                    `Error fetching OCSP response from ${uri}:`,
                    e.message,
                )
                continue
            }
        }

        return undefined
    }

    async requestIssuerCertificate(options?: {
        issuerCertificateUrls?: string[]
    }): Promise<Certificate | undefined> {
        const aiaExt = this.getExtensionByName('AUTHORITY_INFO_ACCESS')
        if (!aiaExt) {
            return undefined
        }

        const aia = aiaExt.extnValue.parseAs(AuthorityInfoAccess)
        const caIssuers = aia.filter(
            (ad) =>
                ad.accessMethod.value === OIDs.AUTHORITY_INFO_ACCESS.CA_ISSUERS,
        )

        if (caIssuers.length === 0) {
            return undefined
        }

        const urls = options?.issuerCertificateUrls ?? []

        for (const ad of caIssuers) {
            if (
                !(
                    ad.accessLocation instanceof
                    GeneralName.uniformResourceIdentifier
                )
            ) {
                console.warn(
                    'Skipping non-URI GeneralName in AuthorityInfoAccess. Type: ' +
                        ad.accessLocation.pkiType,
                )
                continue
            }

            const uri = ad.accessLocation.toString()
            urls.push(uri)
        }

        for (const uri of urls) {
            try {
                const response = await fetch(uri)
                if (!response.ok) {
                    console.warn(
                        `Failed to fetch issuer certificate from ${uri}: ${response.status} ${response.statusText}`,
                    )
                    continue
                }
                const certDer = new Uint8Array(await response.arrayBuffer())
                const certificate = Certificate.fromDer(certDer)
                return certificate
            } catch (e) {
                if (!(e instanceof Error)) {
                    throw e
                }

                console.warn(
                    `Error fetching OCSP response from ${uri}:`,
                    e.message,
                )
                continue
            }
        }

        return undefined
    }

    async isIssuedBy(issuer: Certificate): Promise<boolean> {
        const thisIssuer = this.tbsCertificate.issuer
        const issuerSubject = issuer.tbsCertificate.subject

        if (thisIssuer.toString() !== issuerSubject.toString()) {
            return false
        }

        const thisSignatureAlg = this.signatureAlgorithm
        const issuerPubKeyInfo = issuer.getSubjectPublicKeyInfo()

        return await thisSignatureAlg.verify(
            this.tbsCertificate.toDer(),
            this.signatureValue.bytes,
            issuerPubKeyInfo,
        )
    }

    async isSelfSigned(): Promise<boolean> {
        return this.isIssuedBy(this)
    }

    async validate(
        options?: CertificateValidationOptions,
    ): Promise<CertificateValidationResult> {
        const validator = new CertificateValidator()
        return await validator.validate(this, options)
    }
}
