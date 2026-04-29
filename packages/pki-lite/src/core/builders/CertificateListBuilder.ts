import {
    AlgorithmIdentifier,
    SignatureAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { CertificateList } from '../../x509/CertificateList.js'
import { TBSCertList } from '../../x509/TBSCertList.js'
import { RevokedCertificate } from '../../x509/RevokedCertificate.js'
import { Extension } from '../../x509/Extension.js'
import { Name } from '../../x509/Name.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { Certificate } from '../../x509/Certificate.js'
import { AsyncBuilder } from './types.js'
import { AsymmetricEncryptionAlgorithmParams } from '../crypto/types.js'

/** Default CRL validity period: 30 days */
const DEFAULT_VALIDITY_MS = 30 * 24 * 60 * 60 * 1000

/**
 * Builder class for creating X.509 Certificate Revocation Lists (CRLs).
 *
 * Provides a fluent API for constructing CRLs with revoked certificates,
 * extensions, and signing them with a CA's private key.
 *
 * @example
 * ```typescript
 * const crl = await CertificateList.builder()
 *     .setIssuer('CN=My CA, O=My Org')
 *     .setPrivateKey(caPrivateKey)
 *     .setThisUpdate(new Date())
 *     .setNextUpdate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
 *     .addRevokedCertificate({
 *         serialNumber: 12345,
 *         revocationDate: new Date(),
 *     })
 *     .build()
 * ```
 */
export class CertificateListBuilder implements AsyncBuilder<CertificateList> {
    private issuer?: Name
    private privateKey?: PrivateKeyInfo
    private thisUpdate?: Date
    private nextUpdate?: Date
    private revokedCertificates: RevokedCertificate[] = []
    private extensions: Extension[] = []
    private algorithm?:
        | AsymmetricEncryptionAlgorithmParams
        | SignatureAlgorithmIdentifier
    private version?: 1

    /**
     * Sets the CRL issuer (the CA name).
     *
     * @param issuer Issuer DN as string or Name object
     * @returns This builder for chaining
     */
    setIssuer(issuer: string | Name): this {
        this.issuer = typeof issuer === 'string' ? Name.parse(issuer) : issuer
        return this
    }

    /**
     * Sets the issuer from a CA certificate's subject.
     *
     * @param caCertificate The CA certificate
     * @returns This builder for chaining
     */
    setIssuerFromCertificate(caCertificate: Certificate): this {
        this.issuer = caCertificate.tbsCertificate.subject
        return this
    }

    /**
     * Sets the private key for signing the CRL.
     *
     * @param privateKey The CA's private key
     * @returns This builder for chaining
     */
    setPrivateKey(privateKey: PrivateKeyInfo): this {
        this.privateKey = privateKey
        return this
    }

    /**
     * Sets the thisUpdate time (when this CRL was issued).
     * Defaults to current time if not set.
     *
     * @param date The issue date
     * @returns This builder for chaining
     */
    setThisUpdate(date: Date): this {
        this.thisUpdate = date
        return this
    }

    /**
     * Sets the nextUpdate time (when the next CRL will be issued).
     * Defaults to 30 days after thisUpdate if not set.
     *
     * @param date The next update date
     * @returns This builder for chaining
     */
    setNextUpdate(date: Date): this {
        this.nextUpdate = date
        return this
    }

    /**
     * Adds a revoked certificate entry.
     *
     * @param entry Revoked certificate details, or a RevokedCertificate instance
     * @returns This builder for chaining
     * @example
     * ```typescript
     * builder.addRevokedCertificate({
     *     serialNumber: 12345,
     *     revocationDate: new Date(),
     * })
     * ```
     */
    addRevokedCertificate(
        entry:
            | RevokedCertificate
            | {
                  serialNumber: number | string
                  revocationDate: Date
                  crlEntryExtensions?: Extension[]
              },
    ): this {
        if (entry instanceof RevokedCertificate) {
            this.revokedCertificates.push(entry)
        } else {
            this.revokedCertificates.push(
                new RevokedCertificate({
                    userCertificate: entry.serialNumber,
                    revocationDate: entry.revocationDate,
                    crlEntryExtensions: entry.crlEntryExtensions,
                }),
            )
        }
        // Adding revoked certs triggers v2 CRL
        this.version = 1
        return this
    }

    /**
     * Revokes a certificate by reference. Uses the certificate's serial number
     * and the current time as the revocation date if not provided.
     *
     * @param certificate The certificate to revoke
     * @param revocationDate The revocation date (defaults to now)
     * @returns This builder for chaining
     */
    revokeCertificate(certificate: Certificate, revocationDate?: Date): this {
        return this.addRevokedCertificate({
            serialNumber: certificate.tbsCertificate.serialNumber.toString(),
            revocationDate: revocationDate ?? new Date(),
        })
    }

    /**
     * Adds a CRL extension (e.g., CRL number, authority key identifier).
     *
     * @param extension The extension to add
     * @returns This builder for chaining
     */
    addExtension(extension: Extension): this {
        this.extensions.push(extension)
        // Extensions trigger v2 CRL
        this.version = 1
        return this
    }

    /**
     * Adds multiple CRL extensions.
     *
     * @param extensions The extensions to add
     * @returns This builder for chaining
     */
    addExtensions(...extensions: Extension[]): this {
        for (const ext of extensions) {
            this.addExtension(ext)
        }
        return this
    }

    /**
     * Sets the signature algorithm.
     *
     * @param algorithm Algorithm parameters or SignatureAlgorithmIdentifier
     * @returns This builder for chaining
     */
    setAlgorithm(
        algorithm:
            | AsymmetricEncryptionAlgorithmParams
            | SignatureAlgorithmIdentifier,
    ): this {
        this.algorithm = algorithm
        return this
    }

    private validate(): void {
        if (!this.issuer) {
            throw new Error('Issuer is required')
        }
        if (!this.privateKey) {
            throw new Error('Private key is required for signing CRL')
        }
    }

    /**
     * Builds and signs the CRL.
     *
     * @returns Promise resolving to the signed CertificateList
     */
    async build(): Promise<CertificateList> {
        this.validate()

        const signatureAlgorithm =
            this.algorithm instanceof SignatureAlgorithmIdentifier
                ? this.algorithm
                : AlgorithmIdentifier.signatureAlgorithm(
                      this.algorithm ?? {
                          type: 'RSASSA_PKCS1_v1_5',
                          params: { hash: 'SHA-256' },
                      },
                  )

        const thisUpdate = this.thisUpdate ?? new Date()
        const nextUpdate =
            this.nextUpdate ??
            new Date(thisUpdate.getTime() + DEFAULT_VALIDITY_MS)

        const tbsCertList = new TBSCertList({
            version: this.version,
            signature: signatureAlgorithm,
            issuer: this.issuer!,
            thisUpdate,
            nextUpdate,
            revokedCertificates:
                this.revokedCertificates.length > 0
                    ? this.revokedCertificates
                    : undefined,
            extensions:
                this.extensions.length > 0 ? this.extensions : undefined,
        })

        const signatureValue = await signatureAlgorithm.sign(
            tbsCertList,
            this.privateKey!,
        )

        return new CertificateList({
            tbsCertList,
            signatureAlgorithm,
            signatureValue,
        })
    }
}
