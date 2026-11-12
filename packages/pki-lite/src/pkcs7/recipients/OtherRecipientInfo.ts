import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import {
    Asn1Node,
    der,
    ObjectIdentifierString,
    PkiBase,
    UniversalTag,
} from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an OtherRecipientInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * OtherRecipientInfo ::= SEQUENCE {
 *   oriType OBJECT IDENTIFIER,
 *   oriValue ANY DEFINED BY oriType }
 * ```
 */
export class OtherRecipientInfo extends PkiBase<OtherRecipientInfo> {
    oriType: ObjectIdentifier
    oriValue: Asn1Node

    /**
     * Creates a new OtherRecipientInfo instance.
     */
    constructor(options: {
        oriType: ObjectIdentifierString
        oriValue: Asn1Node
    }) {
        super()
        const { oriType, oriValue } = options
        this.oriType = new ObjectIdentifier({ value: oriType })
        this.oriValue = oriValue
    }

    /**
     * Converts the OtherRecipientInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1Node {
        return der.sequence([this.oriType.toAsn1(), this.oriValue])
    }

    /**
     * Creates an OtherRecipientInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): OtherRecipientInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OtherRecipientInfo',
            )
        }

        const values = asn1.children
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        // Extract oriType
        if (!values[0]?.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for oriType',
            )
        }
        const oriType = der.readOid(values[0])

        // Extract oriValue (any ASN.1 structure)
        const oriValue = values[1]

        return new OtherRecipientInfo({ oriType, oriValue })
    }
}
