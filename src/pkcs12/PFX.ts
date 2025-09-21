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
 * @asn
 * ```asn
 * PFX ::= SEQUENCE {
 *   version     INTEGER {v3(3)}(v3,...),
 *   authSafe    ContentInfo,
 *   macData     MacData OPTIONAL
 * }
 * ```
 */
export class PFX extends PkiBase<PFX> {
    version: number
    authSafe: ContentInfo
    macData?: MacData

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

    get pemHeaders(): string {
        return 'PKCS12'
    }

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
}
