import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1Any,
    Asn1Node,
    der,
    ObjectIdentifierString,
    PkiBase,
    UniversalTag,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an OtherRevocationInfoFormat structure used in PKCS#7/CMS as an
 * alternative to CRL for providing revocation information.
 *
 * @asn
 * ```asn
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *      otherRevInfoFormat OBJECT IDENTIFIER,
 *      otherRevInfo ANY DEFINED BY otherRevInfoFormat
 * }
 * ```
 */
export class OtherRevocationInfoFormat extends PkiBase<OtherRevocationInfoFormat> {
    otherRevInfoFormat: ObjectIdentifier
    otherRevInfo: Any

    /**
     * Creates a new OtherRevocationInfoFormat instance.
     *
     * @param otherRevInfoFormat The format identifier OID
     * @param otherRevInfo The revocation information in the specified format
     */
    constructor(options: {
        otherRevInfoFormat: ObjectIdentifierString
        otherRevInfo: Asn1Any
    }) {
        super()
        this.otherRevInfoFormat = new ObjectIdentifier({
            value: options.otherRevInfoFormat,
        })
        this.otherRevInfo = new Any({ derBytes: options.otherRevInfo })
    }

    /**
     * Converts the OtherRevocationInfoFormat to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        return der.sequence([
            this.otherRevInfoFormat.toAsn1(),
            this.otherRevInfo.toAsn1(),
        ])
    }

    /**
     * Creates an OtherRevocationInfoFormat from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns The OtherRevocationInfoFormat
     */
    static fromAsn1(asn1: Asn1Node): OtherRevocationInfoFormat {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        if (asn1.children.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected 2 elements',
            )
        }

        const [formatAsn1, infoAsn1] = asn1.children

        if (!formatAsn1.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
            )
        }

        // Extract the OID string
        const otherRevInfoFormat = der.readOid(formatAsn1)

        // The other revocation info can be any type, so we extract it based on its type
        const otherRevInfo = new Any({ derBytes: infoAsn1 })

        return new OtherRevocationInfoFormat({
            otherRevInfoFormat,
            otherRevInfo,
        })
    }
}
