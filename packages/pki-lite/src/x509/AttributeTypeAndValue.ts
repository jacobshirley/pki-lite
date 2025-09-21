import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { getOidShortName, getShortNameOid } from '../core/OIDs.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    ObjectIdentifierString,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an attribute type and value pair.
 *
 * @asn
 * ```asn
 * AttributeTypeAndValue ::= SEQUENCE {
 *     type  OBJECT IDENTIFIER,
 *     value ANY DEFINED BY type
 * }
 * ```
 */
export class AttributeTypeAndValue extends PkiBase<AttributeTypeAndValue> {
    type: ObjectIdentifier
    value: Any

    constructor(options: {
        type: ObjectIdentifierString
        value: Asn1Any | string
    }) {
        super()

        const { type, value } = options

        this.type = new ObjectIdentifier({ value: type })
        this.value = new Any({ derBytes: value })
    }

    get shortName(): string {
        return getOidShortName(this.type.value)
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.type.toAsn1(), this.value.toAsn1()],
        })
    }

    toHumanString(): string {
        return `${this.shortName}=${this.value.toHumanString()}`
    }

    static fromAsn1(asn1: Asn1BaseBlock): AttributeTypeAndValue {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('Invalid ASN.1 structure')
        }

        const [type, value] = asn1.valueBlock.value

        if (!(type instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError('Invalid ASN.1 structure')
        }

        return new AttributeTypeAndValue({
            type: type.getValue(),
            value,
        })
    }

    static parse(humanString: string): AttributeTypeAndValue {
        const [shortName, ...valueParts] = humanString.split('=')
        if (!shortName || valueParts.length === 0) {
            throw new Asn1ParseError(
                'Invalid attribute type and value string. Expected format "type=value"',
            )
        }

        const value = valueParts.join('=').trim()

        return new AttributeTypeAndValue({
            type: getShortNameOid(shortName.trim()),
            value,
        })
    }
}
