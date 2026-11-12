import { Any } from '../../asn1/Any.js'
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
 * Represents an OtherKeyAttribute structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * OtherKeyAttribute ::= SEQUENCE {
 *     keyAttrId OBJECT IDENTIFIER,
 *     keyAttr ANY DEFINED BY keyAttrId OPTIONAL
 * }
 * ```
 */
export class OtherKeyAttribute extends PkiBase<OtherKeyAttribute> {
    keyAttrId: ObjectIdentifier
    keyAttr?: PkiBase

    constructor(options: {
        keyAttrId: ObjectIdentifierString
        keyAttr?: PkiBase
    }) {
        super()

        const { keyAttrId, keyAttr } = options

        this.keyAttrId = new ObjectIdentifier({ value: keyAttrId })
        this.keyAttr = keyAttr
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [this.keyAttrId.toAsn1()]

        if (this.keyAttr) {
            values.push(this.keyAttr.toAsn1())
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): OtherKeyAttribute {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OtherKeyAttribute',
            )
        }

        const values = asn1.children
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-2 elements, got ${values.length}`,
            )
        }

        if (!values[0]?.is(UniversalTag.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for keyAttrId',
            )
        }

        const keyIdentifier = der.readOid(values[0])

        return new OtherKeyAttribute({
            keyAttrId: keyIdentifier,
            keyAttr: new Any({ derBytes: values[1] }),
        })
    }

    parseKeyAttrAs<T>(cls: { fromAsn1: (asn1: Asn1Node) => T }): T {
        if (!this.keyAttr) {
            throw new Error('Key attribute is not set')
        }

        return cls.fromAsn1(this.keyAttr.toAsn1())
    }
}
