import {
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
import { Integer } from '../asn1/Integer.js'
import { OIDs } from '../core/OIDs.js'
import { Certificate } from './Certificate.js'
import { Extension } from './Extension.js'
import { directoryName, GeneralName } from './GeneralName.js'
import { IssuingDistributionPoint } from './extensions/IssuingDistributionPoint.js'
import { TBSCertList } from './TBSCertList.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { Name } from './Name.js'
import { RevokedCertificate } from './RevokedCertificate.js'
import { CertificateListBuilder } from '../core/builders/CertificateListBuilder.js'
import { AsymmetricEncryptionAlgorithmParams } from '../core/crypto/types.js'
import { BitString } from '../asn1/BitString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * X.509 Certificate Revocation List (CRL) implementation.
 *
 * A CRL is a time-stamped list identifying revoked certificates that is signed by a CA.
 * CRLs are used to check if a certificate has been revoked before relying on it.
 * Each CRL has a validity period and contains information about when the next update
 * will be available.
 *
 * @asn CertificateList ::= SEQUENCE {
 *   tbsCertList          TBSCertList,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING }
 *
 * @example
 * ```typescript
 * // Create an empty CRL
 * const crl = await CertificateList.createEmpty({
 *     issuer: caName,
 *     privateKey: caPrivateKey,
 *     signatureAlgorithmParams: { type: 'RSASSA_PKCS1_v1_5', params: { hash: 'SHA-256' } }
 * })
 *
 * // Load CRL from PEM
 * const crlFromPem = CertificateList.fromPem(pemString)
 *
 * // Fetch CRL from URL
 * const crlFromUrl = await CertificateList.fetch('http://example.com/ca.crl')
 *
 * // Check the CRL is genuine and current, then whether it lists a certificate
 * if ((await crl.verify(caCertificate)) && crl.isCurrent()) {
 *     const revoked = crl.isRevoked(certificate)
 * }
 * ```
 *
 * @see RFC 5280 Section 5 - CRL and CRL Extensions Profile
 */
/** CRLReason removeFromCRL: a delta CRL entry lifting a hold */
const REMOVE_FROM_CRL = 8

export class CertificateList extends PkiBase<CertificateList> {
    /** The TBS (To Be Signed) portion of the CRL containing the revocation list */
    tbsCertList: TBSCertList

    /** Algorithm used to sign the CRL */
    signatureAlgorithm: AlgorithmIdentifier

    /** Digital signature over the TBS CRL */
    signatureValue: BitString

    /**
     * Creates a new CertificateList instance.
     *
     * @param options Configuration object
     * @param options.tbsCertList The TBS certificate list
     * @param options.signatureAlgorithm The signature algorithm
     * @param options.signatureValue The signature bytes or BitString
     *
     * @example
     * ```typescript
     * const crl = new CertificateList({
     *     tbsCertList,
     *     signatureAlgorithm,
     *     signatureValue: signatureBytes
     * })
     * ```
     */
    constructor(options: {
        tbsCertList: TBSCertList
        signatureAlgorithm: AlgorithmIdentifier
        signatureValue: Uint8Array<ArrayBuffer> | BitString
    }) {
        super()

        this.tbsCertList = options.tbsCertList
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signatureValue = new BitString({
            value: options.signatureValue,
        })
    }

    /**
     * Gets the PEM header for CRL encoding.
     * @returns The PEM header string
     */
    get pemHeader() {
        return 'X509 CRL'
    }

    /** Whether this is a delta CRL (it has a deltaCRLIndicator extension). */
    get isDelta(): boolean {
        return this.baseCrlNumber !== undefined
    }

    /** The CRL number (cRLNumber extension), if present. */
    get crlNumber(): bigint | undefined {
        return this.getExtensionByName('CRL_NUMBER')
            ?.extnValue.parseAs(Integer)
            .toBigInt()
    }

    /** For a delta CRL, the number of the complete CRL it updates (deltaCRLIndicator). */
    get baseCrlNumber(): bigint | undefined {
        return this.getExtensionByName('DELTA_CRL_INDICATOR')
            ?.extnValue.parseAs(Integer)
            .toBigInt()
    }

    /** Which certificates and reasons the CRL covers (issuingDistributionPoint), if limited. */
    get issuingDistributionPoint(): IssuingDistributionPoint | undefined {
        return this.getExtensionByName(
            'ISSUING_DISTRIBUTION_POINT',
        )?.extnValue.parseAs(IssuingDistributionPoint)
    }

    getExtensionByOid(oid: string): Extension | undefined {
        return this.tbsCertList.extensions?.find(
            (extension) => extension.extnID.value === oid,
        )
    }

    getExtensionByName(
        name: keyof typeof OIDs.EXTENSION,
    ): Extension | undefined {
        return this.getExtensionByOid(OIDs.EXTENSION[name])
    }

    /**
     * Whether the CRL is current at `time`: issued (thisUpdate) at or before it, and not
     * yet due for replacement (nextUpdate). A CRL without nextUpdate is never current,
     * since its freshness cannot be established (RFC 5280 5.1.2.5).
     *
     * @param time The time to check at (default now)
     */
    isCurrent(time: Date = new Date()): boolean {
        const { thisUpdate, nextUpdate } = this.tbsCertList
        return (
            thisUpdate <= time && nextUpdate !== undefined && time <= nextUpdate
        )
    }

    /**
     * Verifies that `issuer` signed this CRL: the CRL's issuer name matches the
     * certificate's subject (RFC 5280 7.1), the certificate's key may sign CRLs (keyUsage
     * cRLSign), and the signature verifies over the bytes that were signed.
     *
     * This checks the CRL, not the issuer: whether the issuer's certificate is itself
     * trusted is up to certification path validation (CertificateValidator).
     *
     * @param issuer The certificate of the CRL issuer
     * @returns Whether the CRL is signed by `issuer`
     * @throws If the signature algorithm is not supported
     *
     * @example
     * ```typescript
     * const crl = CertificateList.fromPem(crlPem)
     * if (!(await crl.verify(caCertificate))) throw new Error('CRL not signed by the CA')
     * ```
     */
    async verify(issuer: Certificate): Promise<boolean> {
        if (!this.tbsCertList.issuer.matches(issuer.tbsCertificate.subject)) {
            return false
        }
        if (!issuer.allowsKeyUsage('cRLSign')) return false
        return new SignatureAlgorithmIdentifier(this.signatureAlgorithm).verify(
            this.tbsCertList.toOriginalDer(),
            this.signatureValue.bytes,
            issuer.getSubjectPublicKeyInfo(),
        )
    }

    /**
     * The entry listing `certificate`, if this CRL has one: the same serial number, from
     * the certificate's issuer. On an indirect CRL, the issuer of each entry comes from
     * the certificateIssuer extensions (RFC 5280 5.3.3); otherwise it is the CRL issuer.
     *
     * Does not check that the CRL is genuine or current: see {@link verify} and
     * {@link isCurrent}.
     */
    getRevokedEntry(certificate: Certificate): RevokedCertificate | undefined {
        const serial = certificate.tbsCertificate.serialNumber.toBigInt()
        const indirect = this.issuingDistributionPoint?.indirectCRL ?? false
        let issuers: GeneralName[] = [
            directoryName.fromName(this.tbsCertList.issuer),
        ]
        for (const entry of this.tbsCertList.revokedCertificates ?? []) {
            const named = indirect ? entry.certificateIssuer : undefined
            if (named) issuers = [...named]
            if (entry.serialAsBigInt() !== serial) continue
            const issuedBy = issuers.some(
                (name) =>
                    name instanceof directoryName &&
                    name.matches(certificate.tbsCertificate.issuer),
            )
            if (issuedBy) return entry
        }
        return undefined
    }

    /**
     * Whether this CRL lists `certificate` as revoked (or on hold). An entry with reason
     * removeFromCRL, which a delta CRL uses to lift a hold, does not count.
     *
     * Does not check that the CRL is genuine or current: see {@link verify} and
     * {@link isCurrent}. To check revocation as part of path validation, use
     * CertificateValidator with `checkCRL`.
     */
    isRevoked(certificate: Certificate): boolean {
        const entry = this.getRevokedEntry(certificate)
        return entry !== undefined && entry.reason !== REMOVE_FROM_CRL
    }

    /**
     * Creates an empty CRL with no revoked certificates.
     *
     * This method is useful for initializing a new CRL or for testing purposes.
     * The created CRL will have a validity period of 30 days by default.
     *
     * @param options Configuration for the empty CRL
     * @param options.issuer The name of the CA issuing the CRL
     * @param options.privateKey The CA's private key for signing
     * @param options.signatureAlgorithmParams Optional signature algorithm, defaults to RSA-SHA256
     * @returns Promise resolving to the created empty CRL
     *
     * @example
     * ```typescript
     * const emptyCrl = await CertificateList.createEmpty({
     *     issuer: new Name({ commonName: 'Test CA' }),
     *     privateKey: caPrivateKey,
     *     signatureAlgorithmParams: {
     *         type: 'RSASSA_PKCS1_v1_5',
     *         params: { hash: 'SHA-384' }
     *     }
     * })
     *
     * // CRL is valid for 30 days from creation
     * console.log(emptyCrl.tbsCertList.thisUpdate) // Current time
     * console.log(emptyCrl.tbsCertList.nextUpdate) // 30 days later
     * ```
     */
    /**
     * Creates a fluent builder for constructing CRLs.
     *
     * @returns A new CertificateListBuilder instance
     *
     * @example
     * ```typescript
     * const crl = await CertificateList.builder()
     *     .setIssuer('CN=My CA')
     *     .setPrivateKey(caKey)
     *     .addRevokedCertificate({ serialNumber: 12345, revocationDate: new Date() })
     *     .build()
     * ```
     */
    static builder(): CertificateListBuilder {
        return new CertificateListBuilder()
    }

    static async createEmpty(options: {
        issuer: Name
        privateKey: PrivateKeyInfo
        signatureAlgorithmParams?: AsymmetricEncryptionAlgorithmParams
    }): Promise<CertificateList> {
        const { issuer } = options
        const signatureAlgorithmParams: AsymmetricEncryptionAlgorithmParams =
            options?.signatureAlgorithmParams ?? {
                type: 'RSASSA_PKCS1_v1_5',
                params: {
                    hash: 'SHA-256',
                },
            }
        const signatureAlgorithm = AlgorithmIdentifier.signatureAlgorithm(
            signatureAlgorithmParams,
        )

        // No revoked certificates for now
        const revokedCertificates: RevokedCertificate[] = []

        // Set thisUpdate to now, nextUpdate to +30 days
        const thisUpdate = new Date()
        const nextUpdate = new Date(
            thisUpdate.getTime() + 30 * 24 * 60 * 60 * 1000,
        )

        // TBSCertList version 1 (v2), as per RFC if extensions present
        const tbsCertList = new TBSCertList({
            version: 1,
            signature: signatureAlgorithm,
            issuer,
            thisUpdate,
            nextUpdate,
            revokedCertificates,
        })

        return new CertificateList({
            tbsCertList,
            signatureAlgorithm,
            signatureValue: await signatureAlgorithm.sign(
                tbsCertList,
                options.privateKey,
            ),
        })
    }

    /**
     * Converts the CRL to its ASN.1 representation.
     *
     * @returns ASN.1 structure representing the CRL
     *
     * @example
     * ```typescript
     * const asn1 = crl.toAsn1()
     * const der = asn1.toBER(false) // Convert to DER encoding
     * ```
     */
    toAsn1(): Asn1BaseBlock {
        // Create the main CertificateList sequence
        return new asn1js.Sequence({
            value: [
                this.tbsCertList.toAsn1(),
                this.signatureAlgorithm.toAsn1(),
                this.signatureValue.toAsn1(),
            ],
        })
    }

    /**
     * Creates a CertificateList from an ASN.1 structure.
     *
     * Parses the ASN.1 SEQUENCE structure and extracts the TBS certificate list,
     * signature algorithm, and signature value components.
     *
     * @param asn1 The ASN.1 structure to parse
     * @returns The parsed CertificateList object
     * @throws Asn1ParseError if the ASN.1 structure is invalid
     *
     * @example
     * ```typescript
     * const asn1 = derToAsn1(crlBytes)
     * const crl = CertificateList.fromAsn1(asn1)
     * ```
     */
    static fromAsn1(asn1: Asn1BaseBlock): CertificateList {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE but got ' +
                    asn1.constructor.name,
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 3) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 3 elements',
            )
        }

        // Extract tbsCertList
        if (!(values[0] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for tbsCertList',
            )
        }
        const tbsCertList = TBSCertList.fromAsn1(values[0])

        // Extract signatureAlgorithm
        if (!(values[1] instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE for signatureAlgorithm',
            )
        }
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(values[1])

        // Extract signatureValue
        if (!(values[2] instanceof asn1js.BitString)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected BIT STRING for signatureValue',
            )
        }
        const signatureValue = new Uint8Array(values[2].valueBlock.valueHexView)

        return new CertificateList({
            tbsCertList,
            signatureAlgorithm,
            signatureValue,
        })
    }

    /**
     * Creates a CertificateList from DER-encoded bytes.
     *
     * @param der The DER-encoded CRL bytes
     * @returns The parsed CertificateList
     * @throws Error if DER parsing fails
     *
     * @example
     * ```typescript
     * const crl = CertificateList.fromDer(crlBytes)
     * ```
     */
    static fromDer(der: Uint8Array<ArrayBuffer>): CertificateList {
        return CertificateList.fromAsn1(derToAsn1(der))
    }

    /**
     * Creates a CertificateList from PEM-encoded text.
     *
     * @param pem The PEM-encoded CRL string
     * @returns The parsed CertificateList
     * @throws Error if PEM parsing fails
     *
     * @example
     * ```typescript
     * const pemCrl = `
     * -----BEGIN X509 CRL-----
     * MIIBzDCBtQIBATANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJVUzELMAkGA1UE
     * ...
     * -----END X509 CRL-----`
     *
     * const crl = CertificateList.fromPem(pemCrl)
     * ```
     */
    static fromPem(pem: string): CertificateList {
        return CertificateList.fromDer(pemToDer(pem, 'X509 CRL'))
    }

    /**
     * Fetches a CRL from a URL and parses it.
     *
     * This is commonly used to retrieve CRLs from Certificate Distribution Points
     * specified in X.509 certificates.
     *
     * @param url The URL to fetch the CRL from
     * @returns Promise resolving to the fetched and parsed CRL
     * @throws Error if the HTTP request fails or CRL parsing fails
     *
     * @example
     * ```typescript
     * // Fetch CRL from a CA's distribution point
     * const crl = await CertificateList.fetch('http://crl.example.com/ca.crl')
     *
     * // Check certificate status
     * const serialNumber = certificate.tbsCertificate.serialNumber
     * if (crl.tbsCertList.isRevoked(serialNumber)) {
     *     console.log('Certificate is revoked')
     * }
     * ```
     */
    static async fetch(url: string): Promise<CertificateList> {
        const res = await fetch(url)
        if (!res.ok) {
            throw new Error(
                `Failed to fetch CRL from ${url}: ${res.statusText}`,
            )
        }
        const der = new Uint8Array(await res.arrayBuffer())
        return CertificateList.fromDer(der)
    }
}
