import { PFX } from '../../pkcs12/PFX.js'
import { Certificate } from '../../x509/Certificate.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { EncryptedPrivateKeyInfo } from '../../keys/EncryptedPrivateKeyInfo.js'
import { AuthenticatedSafe } from '../../pkcs12/AuthenticatedSafe.js'
import { SafeBag } from '../../pkcs12/SafeBag.js'
import { SafeContents } from '../../pkcs12/SafeContents.js'
import { CertBag } from '../../pkcs12/CertBag.js'
import { MacData } from '../../pkcs12/MacData.js'
import { DigestInfo } from '../../pkcs12/DigestInfo.js'
import { ContentInfo } from '../../pkcs7/ContentInfo.js'
import { EncryptedData } from '../../pkcs7/EncryptedData.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { BMPString } from '../../asn1/BMPString.js'
import { Attribute } from '../../x509/Attribute.js'
import { OIDs } from '../OIDs.js'
import { AsyncBuilder } from './types.js'

/**
 * Builder class for creating PKCS#12 (PFX) files.
 *
 * Provides a fluent API for assembling certificates and private keys into
 * a password-protected PKCS#12 container. Uses PBES2 (PBKDF2 + AES-256-CBC)
 * for encryption and HMAC-SHA-256 with PKCS#12 password-based key derivation
 * (RFC 7292 Appendix B) for the MAC.
 *
 * @example
 * ```typescript
 * const pfx = await PFX.builder()
 *     .addCertificate(clientCert)
 *     .addCertificate(caCert)
 *     .addPrivateKey(privateKey)
 *     .setPassword('s3cret')
 *     .setFriendlyName('My Identity')
 *     .build()
 *
 * const pem = pfx.toPem()
 * ```
 */
export class PFXBuilder implements AsyncBuilder<PFX> {
    private certificates: Certificate[] = []
    private privateKeys: PrivateKeyInfo[] = []
    private password?: string | Uint8Array<ArrayBuffer>
    private friendlyName?: string
    private iterations: number = 2048

    /**
     * Adds a certificate to the PFX. Can be called multiple times to add a chain.
     *
     * @param certificates One or more certificates
     * @returns This builder for chaining
     */
    addCertificate(...certificates: Certificate[]): this {
        this.certificates.push(...certificates)
        return this
    }

    /**
     * Adds a private key to the PFX. The key will be password-encrypted.
     *
     * @param privateKeys One or more private keys
     * @returns This builder for chaining
     */
    addPrivateKey(...privateKeys: PrivateKeyInfo[]): this {
        this.privateKeys.push(...privateKeys)
        return this
    }

    /**
     * Sets the password used to encrypt the private keys and compute the MAC.
     *
     * @param password The password (string or bytes)
     * @returns This builder for chaining
     */
    setPassword(password: string | Uint8Array<ArrayBuffer>): this {
        this.password = password
        return this
    }

    /**
     * Sets an optional friendly name attached to the certificate/key bags.
     *
     * @param friendlyName The friendly name
     * @returns This builder for chaining
     */
    setFriendlyName(friendlyName: string): this {
        this.friendlyName = friendlyName
        return this
    }

    /**
     * Sets the number of iterations used by PBKDF2 and the MAC derivation.
     * Defaults to 2048.
     *
     * @param iterations Iteration count
     * @returns This builder for chaining
     */
    setIterations(iterations: number): this {
        this.iterations = iterations
        return this
    }

    private validate(): void {
        if (this.password === undefined) {
            throw new Error('Password is required')
        }
        if (this.certificates.length === 0 && this.privateKeys.length === 0) {
            throw new Error(
                'At least one certificate or private key is required',
            )
        }
    }

    /**
     * Builds the PFX container.
     *
     * @returns Promise resolving to the PFX instance
     */
    async build(): Promise<PFX> {
        this.validate()
        const password = this.password!
        const iterations = this.iterations

        // Common bag attributes (friendlyName)
        const bagAttributes = this.friendlyName
            ? [Attribute.friendlyName(this.friendlyName)]
            : undefined

        // ---- Build key SafeContents (one ContentInfo of type Data) ----
        const keyBags: SafeBag[] = []
        for (const privateKey of this.privateKeys) {
            const encryptedKey = await EncryptedPrivateKeyInfo.create(
                privateKey,
                password,
                { iterations },
            )
            keyBags.push(
                new SafeBag({
                    bagId: OIDs.PKCS12.BAGS.PKCS8_SHROUDED_KEY_BAG,
                    bagValue: encryptedKey,
                    bagAttributes,
                }),
            )
        }

        // ---- Build cert SafeContents (one ContentInfo of type EncryptedData) ----
        const certBags: SafeBag[] = []
        for (const certificate of this.certificates) {
            certBags.push(
                new SafeBag({
                    bagId: OIDs.PKCS12.BAGS.CERT_BAG,
                    bagValue: new CertBag({
                        certId: OIDs.PKCS12.CERT_TYPES.X509_CERT,
                        certValue: new OctetString({
                            bytes: certificate.toDer(),
                        }),
                    }),
                    bagAttributes,
                }),
            )
        }

        const contentInfos: ContentInfo[] = []

        if (certBags.length > 0) {
            const safeContents = new SafeContents(...certBags)
            const encryptedData = await EncryptedData.create({
                contentType: 'DATA',
                data: safeContents.toDer(),
                password,
                iterations,
            })
            contentInfos.push(encryptedData.asCms())
        }

        if (keyBags.length > 0) {
            const safeContents = new SafeContents(...keyBags)
            contentInfos.push(
                new ContentInfo({
                    contentType: OIDs.PKCS7.DATA,
                    content: new OctetString({ bytes: safeContents.toDer() }),
                }),
            )
        }

        const authenticatedSafe = new AuthenticatedSafe(...contentInfos)
        const authSafeDer = authenticatedSafe.toDer()

        // ---- Compute MAC over the AuthenticatedSafe DER ----
        const macData = await MacData.create(
            authSafeDer,
            password,
            iterations,
            'SHA-256',
        )

        return new PFX({
            authSafe: new ContentInfo({
                contentType: OIDs.PKCS7.DATA,
                content: new OctetString({ bytes: authSafeDer }),
            }),
            macData,
        })
    }
}
