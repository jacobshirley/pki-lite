import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { ContentInfo } from './ContentInfo.js'
import { OIDs, Pkcs7ContentType } from '../core/OIDs.js'
import { EncryptedDataBuilder } from '../core/builders/EncryptedDataBuilder.js'

/**
 * Represents a PKCS#7 EncryptedData structure.
 *
 * @asn
 * ```asn
 * EncryptedData ::= SEQUENCE {
 *      version INTEGER,
 *      encryptedContentInfo EncryptedContentInfo
 *      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 * ```
 */
export class EncryptedData extends PkiBase<EncryptedData> {
    version: number
    encryptedContentInfo: EncryptedContentInfo

    constructor(options: {
        version: number
        encryptedContentInfo: EncryptedContentInfo
    }) {
        super()
        const { version, encryptedContentInfo } = options

        this.version = version
        this.encryptedContentInfo = encryptedContentInfo
    }

    /**
     * Converts the EncryptedData to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        return der.sequence([
            der.integer(this.version),
            this.encryptedContentInfo.toAsn1(),
        ])
    }

    /**
     * Creates an EncryptedData from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): EncryptedData {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.children
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        // Version
        if (!values[0]?.is(UniversalTag.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = der.readNumber(values[0])

        // EncryptedContentInfo
        const encryptedContentInfo = EncryptedContentInfo.fromAsn1(values[1])

        return new EncryptedData({ version, encryptedContentInfo })
    }

    /**
     * Returns a builder for creating encrypted data.
     *
     * @returns A new EncryptedDataBuilder instance
     */
    static builder(): EncryptedDataBuilder {
        return new EncryptedDataBuilder()
    }

    /**
     * Creates an encrypted data structure using PBES2 (PBKDF2 + AES-256-CBC).
     *
     * @param options Configuration for creating encrypted data
     * @returns Promise resolving to the encrypted data
     */
    static async create(options: {
        contentType: Pkcs7ContentType
        data: Uint8Array<ArrayBuffer>
        password: string | Uint8Array<ArrayBuffer>
        salt?: Uint8Array<ArrayBuffer>
        iv?: Uint8Array<ArrayBuffer>
        iterations?: number
    }): Promise<EncryptedData> {
        const builder = EncryptedData.builder()
            .setContentType(options.contentType)
            .setData(options.data)
            .setPassword(options.password)

        if (options.salt) builder.setSalt(options.salt)
        if (options.iv) builder.setIV(options.iv)
        if (options.iterations) builder.setIterations(options.iterations)

        return builder.build()
    }

    asCms(): ContentInfo {
        return new ContentInfo({
            contentType: OIDs.PKCS7.ENCRYPTED_DATA,
            content: this,
        })
    }
}
