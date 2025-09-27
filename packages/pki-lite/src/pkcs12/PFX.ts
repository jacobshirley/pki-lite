import { ContentInfo } from '../pkcs7/ContentInfo.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    derToAsn1,
    pemToDer,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { MacData } from './MacData.js'
import { OIDs } from '../core/OIDs.js'
import { SafeBag } from './SafeBag.js'
import { AuthenticatedSafe } from './AuthenticatedSafe.js'
import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { EncryptedPrivateKeyInfo } from '../keys/EncryptedPrivateKeyInfo.js'
import { CertBag } from './CertBag.js'
import { Certificate } from '../x509/Certificate.js'
import { OctetString } from '../asn1/OctetString.js'

/**
 * Represents a PFX structure in a PKCS#12 file.
 *
 * PFX (Personal Information Exchange) is the main container format for PKCS#12
 * files. It can store private keys, certificates, and other cryptographic objects
 * in a password-protected format. PKCS#12 files are commonly used for importing
 * and exporting certificates and private keys between applications.
 *
 * @asn
 * ```asn
 * PFX ::= SEQUENCE {
 *   version     INTEGER {v3(3)}(v3,...),
 *   authSafe    ContentInfo,
 *   macData     MacData OPTIONAL
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Load PKCS#12 file from PEM
 * const p12Pem = '-----BEGIN PKCS12-----...-----END PKCS12-----'
 * const pfx = PFX.fromPem(p12Pem)
 *
 * // Extract certificates and private keys
 * const items = await pfx.extractItems('password123')
 * const certificate = items.certificates[0]
 * const privateKey = items.privateKeys[0]
 *
 * // Create new PKCS#12 file
 * const newPfx = await PFX.create({
 *     certificates: [clientCert, caCert],
 *     privateKeys: [privateKey],
 *     password: 'newPassword',
 *     friendlyName: 'My Certificate'
 * })
 *
 * // Save as PEM
 * const pemData = newPfx.toPem()
 * ```
 */
export class PFX extends PkiBase<PFX> {
    /**
     * Version number (typically 3 for PKCS#12 v1.0).
     */
    version: number

    /**
     * The authenticated safe containing the encrypted content.
     */
    authSafe: ContentInfo

    /**
     * Optional MAC data for integrity verification.
     */
    macData?: MacData

    /**
     * Creates a new PFX instance.
     *
     * @param options Configuration object
     * @param options.version Version number (defaults to 3)
     * @param options.authSafe The authenticated safe content
     * @param options.macData Optional MAC data for integrity
     */
    constructor(options: {
        version?: number
        authSafe: ContentInfo
        macData?: MacData
    }) {
        super()
        this.version = options.version ?? 3
        this.authSafe = options.authSafe
        this.macData = options.macData
    }

    /**
     * Gets the PEM header name for PKCS#12 files.
     */
    get pemHeaders(): string {
        return 'PKCS12'
    }

    /**
     * Converts this PFX to its ASN.1 representation.
     *
     * @returns The ASN.1 SEQUENCE structure
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            new asn1js.Integer({ value: this.version }),
            this.authSafe.toAsn1(),
        ]
        if (this.macData) {
            values.push(this.macData.toAsn1())
        }
        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PFX {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('PFX: expected SEQUENCE')
        }
        const values = asn1.valueBlock.value
        if (values.length < 2 || values.length > 3) {
            throw new Asn1ParseError('PFX: expected 2 or 3 elements')
        }
        const ver = values[0]
        const ci = values[1]
        if (!(ver instanceof asn1js.Integer)) {
            throw new Asn1ParseError('PFX: version must be INTEGER')
        }
        const version = ver.valueBlock.valueDec
        const authSafe = ContentInfo.fromAsn1(ci)
        let macData: MacData | undefined
        if (values.length === 3) {
            macData = MacData.fromAsn1(values[2])
        }
        return new PFX({ version, authSafe, macData })
    }

    static fromDer(der: Uint8Array): PFX {
        return PFX.fromAsn1(derToAsn1(der))
    }

    static fromPem(pem: string): PFX {
        const der = pemToDer(pem, ['PFX', 'PKCS12'])
        return PFX.fromDer(der)
    }

    async getBags(password: string | Uint8Array): Promise<SafeBag[]> {
        if (this.authSafe.contentType.isNot(OIDs.PKCS7.DATA)) {
            throw new Error(
                `Unsupported authSafe contentType: ${this.authSafe.contentType}`,
            )
        }

        const content = this.authSafe.parseContentAs(AuthenticatedSafe)
        return await content.getBags(password)
    }

    async getBagsByName(
        bagName: keyof typeof OIDs.PKCS12.BAGS,
        password: string | Uint8Array,
    ): Promise<SafeBag[]> {
        const bagId = OIDs.PKCS12.BAGS[bagName]
        if (!bagId) {
            throw new Error(`Unknown bag name: ${bagName}`)
        }

        if (this.authSafe.contentType.isNot(OIDs.PKCS7.DATA)) {
            throw new Error(
                `Unsupported authSafe contentType: ${this.authSafe.contentType}`,
            )
        }

        const content = this.authSafe.parseContentAs(AuthenticatedSafe)
        return await content.getBagsByName(bagName, password)
    }

    async getPrivateKeys(
        password: string | Uint8Array,
    ): Promise<PrivateKeyInfo[]> {
        const bags = await this.getBagsByName(
            'PKCS8_SHROUDED_KEY_BAG',
            password,
        )
        return await Promise.all(
            bags.map((bag) =>
                bag.getAs(EncryptedPrivateKeyInfo).decrypt(password),
            ),
        )
    }

    async getX509Certificates(
        password: string | Uint8Array,
    ): Promise<Certificate[]> {
        const bags = await this.getBagsByName('CERT_BAG', password)
        const certs: Certificate[] = []
        for (const bag of bags) {
            const certBag = bag.getAs(CertBag)
            if (certBag.certId.isNot(OIDs.PKCS12.CERT_TYPES.X509_CERT)) {
                continue
            }

            const octet = certBag.certValue.parseAs(OctetString)
            const cert = octet.parseAs(Certificate)
            certs.push(cert)
        }
        return certs
    }

    async extractItems(password: string | Uint8Array): Promise<{
        privateKeys: PrivateKeyInfo[]
        certificates: Certificate[]
    }> {
        const [privateKeys, certificates] = await Promise.all([
            this.getPrivateKeys(password),
            this.getX509Certificates(password),
        ])
        return { privateKeys, certificates }
    }

    /**
     * Creates a new PFX instance containing the given certificates and private keys.
     *
     * @param options Configuration object
     * @param options.certificates Array of certificates to include
     * @param options.privateKeys Array of private keys to include
     * @param options.password Password to encrypt the private keys
     * @param options.friendlyName Optional friendly name for the key/cert pairs
     * @returns A new PFX instance
     */
    static async create(options: {
        certificates: Certificate[]
        privateKeys: PrivateKeyInfo[]
        password: string | Uint8Array
        friendlyName?: string
    }): Promise<PFX> {
        throw new Error('Not implemented yet')
    }
}
