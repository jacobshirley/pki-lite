import {
    Asn1Node,
    der,
    ObjectIdentifierString,
    ParseableAsn1,
    PkiBase,
    TagClass,
    UniversalTag,
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
        encryptedContent?: Uint8Array<ArrayBuffer>
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
    toAsn1(): Asn1Node {
        const values = [
            this.contentType.toAsn1(),
            this.contentEncryptionAlgorithm.toAsn1(),
        ]

        if (this.encryptedContent) {
            const encryptedData = this.encryptedContent.toAsn1().implicit(0) // [0] IMPLICIT
            values.push(encryptedData)
        }

        return der.sequence(values)
    }

    /**
     * Creates an EncryptedContentInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): EncryptedContentInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.children
        if (values.length < 2 || values.length > 3) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2-3 elements, got ${values.length}`,
            )
        }

        // ContentType
        if (!values[0]?.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for contentType',
            )
        }
        const contentType = der.readOid(values[0])

        // ContentEncryptionAlgorithm
        const contentEncryptionAlgorithm = AlgorithmIdentifier.fromAsn1(
            values[1],
        )

        // EncryptedContent (optional)
        let encryptedContent: Uint8Array<ArrayBuffer> | undefined = undefined
        // encryptedContent [0] IMPLICIT OCTET STRING: primitive in DER, but BER writers
        // that stream (`openssl cms -stream`) use a constructed [0] of OCTET STRING chunks
        if (
            values.length > 2 &&
            values[2].tagClass === TagClass.Context &&
            values[2].tag === 0
        ) {
            encryptedContent = values[2].bytes()
        }

        return new EncryptedContentInfo({
            contentType,
            contentEncryptionAlgorithm,
            encryptedContent,
        })
    }

    async decrypt(key: string | Uint8Array<ArrayBuffer>): Promise<OctetString> {
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
        key: string | Uint8Array<ArrayBuffer>,
        parseAs: ParseableAsn1<T>,
    ): Promise<T> {
        const octetString = await this.decrypt(key)
        return octetString.parseAs(parseAs)
    }
}
