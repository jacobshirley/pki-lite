import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import {
    Asn1Any,
    Asn1Node,
    der,
    derToAsn1,
    ObjectIdentifierString,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a CMS ContentInfo structure.
 *
 * @asn
 * ```asn
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 * ```
 */
export class ContentInfo extends PkiBase<ContentInfo> {
    contentType: ObjectIdentifier
    content?: Any

    constructor(options: {
        contentType: ObjectIdentifierString
        content?: Asn1Any
    }) {
        super()

        const { contentType, content } = options

        this.contentType = new ObjectIdentifier({ value: contentType })
        this.content = content ? new Any({ derBytes: content }) : undefined
    }

    /**
     * Converts the ContentInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [this.contentType.toAsn1()]

        if (this.content !== undefined) {
            // Wrap in [0] EXPLICIT context tag
            values.push(der.constructed(0, [this.content.toAsn1()]))
        }

        return der.sequence(values)
    }

    parseContentAs<T extends PkiBase<any>>(cls: {
        fromAsn1?(asn1: Asn1Node): T
        fromDer?(der: Uint8Array<ArrayBuffer>): T
    }): T {
        if (this.content) {
            try {
                return this.content.parseAs(OctetString).parseAs(cls)
            } catch {
                return this.content.parseAs(cls)
            }
        }

        throw new Error('Content is not defined')
    }

    /**
     * Creates a ContentInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A ContentInfo object
     */
    static fromAsn1(asn1: Asn1Node): ContentInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.children
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-2 elements, got ${values.length}`,
            )
        }

        // ContentType
        if (!values[0]?.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for contentType',
            )
        }
        const contentType = der.readOid(values[0])

        // Content (optional)
        let content: Asn1Any | undefined = undefined
        if (values.length > 1) {
            // Check if the content is properly tagged with [0] EXPLICIT
            if (
                !values[1]?.constructed ||
                values[1].tagClass !== TagClass.Context || // CONTEXT-SPECIFIC
                values[1].tag !== 0
            ) {
                // [0]
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected [0] EXPLICIT tag for content',
                )
            }

            const contentValues = values[1].children

            if (contentValues.length !== 1) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected exactly one content element inside [0] tag',
                )
            }

            content = new Any({ derBytes: contentValues[0] })
        }

        return new ContentInfo({
            contentType,
            content,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): ContentInfo {
        const asn1 = derToAsn1(der)
        return ContentInfo.fromAsn1(asn1)
    }
}
