import {
    Asn1BaseBlock,
    asn1js,
    ObjectIdentifierString,
    ParseableAsn1,
    PkiBase,
} from '../core/PkiBase.js'
import {
    AlgorithmIdentifier,
    ContentEncryptionAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OctetString } from '../asn1/OctetString.js'

/**
 * Represents encrypted content information.
 *
 * @asn
 * ```asn
 * EncryptedContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
 * }
 *
 * EncryptedContent ::= OCTET STRING
 * ```
 */
export class EncryptedContentInfo extends PkiBase<EncryptedContentInfo> {
    contentType: ObjectIdentifier
    contentEncryptionAlgorithm: ContentEncryptionAlgorithmIdentifier
    encryptedContent?: OctetString

    constructor(options: {
        contentType: ObjectIdentifierString
        contentEncryptionAlgorithm: AlgorithmIdentifier
        encryptedContent?: Uint8Array
    }) {
        super()
        const { contentType, contentEncryptionAlgorithm, encryptedContent } =
            options

        this.contentType = new ObjectIdentifier({ value: contentType })
        this.contentEncryptionAlgorithm =
            new ContentEncryptionAlgorithmIdentifier(contentEncryptionAlgorithm)
        this.encryptedContent = options?.encryptedContent
            ? new OctetString({ bytes: options.encryptedContent })
            : undefined
    }

    /**
     * Converts the EncryptedContentInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values = [
            this.contentType.toAsn1(),
            this.contentEncryptionAlgorithm.toAsn1(),
        ]

        if (this.encryptedContent) {
            const encryptedData = this.encryptedContent.toAsn1()
            encryptedData.idBlock.tagClass = 3 // CONTEXT_SPECIFIC
            encryptedData.idBlock.tagNumber = 0 // [0]
            values.push(encryptedData)
        }

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates an EncryptedContentInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): EncryptedContentInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 2 || values.length > 3) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2-3 elements, got ${values.length}`,
            )
        }

        // ContentType
        if (!(values[0] instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for contentType',
            )
        }
        const contentType = values[0].valueBlock.toString()

        // ContentEncryptionAlgorithm
        const contentEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(
            values[1],
        )

        // EncryptedContent (optional)
        let encryptedContent: Uint8Array | undefined = undefined
        if (
            values.length > 2 &&
            (values[2] instanceof asn1js.Primitive ||
                values[2] instanceof asn1js.OctetString)
        ) {
            const primitive = values[2] as asn1js.Primitive | asn1js.OctetString
            if (
                primitive.idBlock.tagClass === 3 &&
                primitive.idBlock.tagNumber === 0
            ) {
                encryptedContent = new Uint8Array(
                    primitive.valueBlock.valueHexView,
                )
            }
        }

        return new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
            encryptedContent,
        })
    }

    async decrypt(key: string | Uint8Array): Promise<OctetString> {
        if (!this.encryptedContent) {
            throw new Error('No encrypted content to decrypt')
        }

        if (typeof key === 'string') {
            key = new TextEncoder().encode(key)
        }

        const decryptedBytes = await this.contentEncryptionAlgorithm.decrypt(
            this.encryptedContent.bytes,
            key,
        )
        return new OctetString({ bytes: decryptedBytes })
    }

    async decryptAs<T>(
        key: string | Uint8Array,
        parseAs: ParseableAsn1<T>,
    ): Promise<T> {
        const octetString = await this.decrypt(key)
        return octetString.parseAs(parseAs)
    }
}
