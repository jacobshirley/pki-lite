import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    derToAsn1,
    ObjectIdentifierString,
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
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [this.contentType.toAsn1()]

        if (this.content !== undefined) {
            // Wrap in [0] EXPLICIT context tag
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [this.content.toAsn1()],
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    parseContentAs<T extends PkiBase<any>>(cls: {
        fromAsn1?(asn1: Asn1BaseBlock): T
        fromDer?(der: Uint8Array): T
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
    static fromAsn1(asn1: Asn1BaseBlock): ContentInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-2 elements, got ${values.length}`,
            )
        }

        // ContentType
        if (!(values[0] instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for contentType',
            )
        }
        const contentType = values[0].valueBlock.toString()

        // Content (optional)
        let content: Asn1Any | undefined = undefined
        if (values.length > 1) {
            // Check if the content is properly tagged with [0] EXPLICIT
            if (
                !(values[1] instanceof asn1js.Constructed) ||
                values[1].idBlock.tagClass !== 3 || // CONTEXT-SPECIFIC
                values[1].idBlock.tagNumber !== 0
            ) {
                // [0]
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected [0] EXPLICIT tag for content',
                )
            }

            const contentValues = (values[1] as asn1js.Constructed).valueBlock
                .value

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

    static fromDer(der: Uint8Array): ContentInfo {
        const asn1 = derToAsn1(der)
        return ContentInfo.fromAsn1(asn1)
    }
}
