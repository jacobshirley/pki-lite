import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1BaseBlock,
    asn1js,
    ObjectIdentifierString,
    PkiBase,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a EncapsulatedContentInfo structure.
 *
 * @asn
 * ```asn
 * EncapsulatedContentInfo ::= SEQUENCE {
 *      eContentType ContentType,
 *      eContent [0] EXPLICIT OCTET STRING OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 * ```
 */
export class EncapsulatedContentInfo extends PkiBase<EncapsulatedContentInfo> {
    eContentType: ObjectIdentifier
    eContent?: Uint8Array<ArrayBuffer>

    constructor(options: {
        eContentType: ObjectIdentifierString
        eContent?: Uint8Array<ArrayBuffer> | Uint8Array | string
    }) {
        super()
        const { eContentType, eContent } = options

        this.eContentType = new ObjectIdentifier({ value: eContentType })
        this.eContent = eContent
            ? new Uint8Array(
                  typeof eContent === 'string'
                      ? new TextEncoder().encode(eContent)
                      : eContent,
              )
            : undefined
    }

    /**
     * Converts the EncapsulatedContentInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [this.eContentType.toAsn1()]

        if (this.eContent !== undefined) {
            // Convert content based on its type
            const contentAsn1 = new asn1js.OctetString({
                valueHex: this.eContent,
            })

            // Wrap in [0] EXPLICIT context tag
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [contentAsn1],
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    /**
     * Creates a EncapsulatedContentInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A EncapsulatedContentInfo object
     */
    static fromAsn1(asn1: Asn1BaseBlock): EncapsulatedContentInfo {
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
        let content: Uint8Array<ArrayBuffer> | undefined = undefined
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

            if (!(contentValues[0] instanceof asn1js.OctetString)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected OCTET STRING for eContent',
                )
            }

            content = new Uint8Array(contentValues[0].valueBlock.valueHexView)
        }

        return new EncapsulatedContentInfo({
            eContentType: contentType,
            eContent: content,
        })
    }
}
