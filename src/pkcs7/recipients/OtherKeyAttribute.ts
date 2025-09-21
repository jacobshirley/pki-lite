import { Any } from '../../asn1/Any.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import {
    Asn1BaseBlock,
    asn1js,
    ObjectIdentifierString,
    PkiBase,
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

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [this.keyAttrId.toAsn1()]

        if (this.keyAttr) {
            values.push(this.keyAttr.toAsn1())
        }

        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): OtherKeyAttribute {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OtherKeyAttribute',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 1-2 elements, got ${values.length}`,
            )
        }

        if (!(values[0] instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected ObjectIdentifier for keyAttrId',
            )
        }

        const keyIdentifier = values[0].valueBlock.toString()

        return new OtherKeyAttribute({
            keyAttrId: keyIdentifier,
            keyAttr: new Any({ derBytes: values[1] }),
        })
    }

    parseKeyAttrAs<T>(cls: { fromAsn1: (asn1: Asn1BaseBlock) => T }): T {
        if (!this.keyAttr) {
            throw new Error('Key attribute is not set')
        }

        return cls.fromAsn1(this.keyAttr.toAsn1())
    }
}
