import { OctetString } from '../asn1/OctetString.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1Node,
    der,
    ObjectIdentifierString,
    PkiBase,
    TagClass,
    UniversalTag,
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
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [this.eContentType.toAsn1()]

        if (this.eContent !== undefined) {
            // Convert content based on its type
            const contentAsn1 = der.octetString(this.eContent)

            // Wrap in [0] EXPLICIT context tag
            values.push(der.constructed(0, [contentAsn1]))
        }

        return der.sequence(values)
    }

    /**
     * Creates a EncapsulatedContentInfo from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns A EncapsulatedContentInfo object
     */
    static fromAsn1(asn1: Asn1Node): EncapsulatedContentInfo {
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
        let content: Uint8Array<ArrayBuffer> | undefined = undefined
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

            if (!contentValues[0]?.is(UniversalTag.OctetString)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected OCTET STRING for eContent',
                )
            }

            // May be a constructed (chunked) OCTET STRING in BER, e.g. `openssl cms -stream`
            content = contentValues[0].bytes()
        }

        return new EncapsulatedContentInfo({
            eContentType: contentType,
            eContent: content,
        })
    }
}
