import { OIDs } from '../core/OIDs.js'
import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
    ObjectIdentifierString,
    PkiBase,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 OBJECT IDENTIFIER value.
 *
 * @asn
 * ```asn
 * ObjectIdentifier ::= <value>
 * ```
 */
export class ObjectIdentifier extends PkiBase<ObjectIdentifier> {
    value: string

    constructor(options: { value: ObjectIdentifierString | ObjectIdentifier }) {
        super()
        const { value } = options

        if (!value && value !== '') {
            throw new Error(
                'ObjectIdentifier value cannot be undefined or null',
            )
        }

        if (value instanceof ObjectIdentifier) {
            this.value = value.value
        } else if (typeof value === 'string') {
            this.value = value
        } else if (value && typeof value.toString === 'function') {
            this.value = value.toString()
        } else {
            throw new Error(
                'ObjectIdentifier value must be a string, ObjectIdentifier instance, or object with toString() method',
            )
        }
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.ObjectIdentifier({ value: this.value })
    }

    static fromAsn1(asn1: Asn1BaseBlock): ObjectIdentifier {
        if (!(asn1 instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OBJECT IDENTIFIER',
            )
        }

        const oidValue = asn1.valueBlock.toString()
        if (!oidValue) {
            throw new Asn1ParseError(
                'Invalid ObjectIdentifier: no value found in ASN.1 structure',
            )
        }

        return new ObjectIdentifier({ value: oidValue })
    }

    static fromDer(bytes: Uint8Array): ObjectIdentifier {
        return ObjectIdentifier.fromAsn1(derToAsn1(bytes))
    }

    toString() {
        return this.value
    }

    is(other: ObjectIdentifier | string): boolean {
        if (other instanceof ObjectIdentifier) {
            return this.value === other.value
        } else if (typeof other === 'string') {
            return this.value === other
        }
        return false
    }

    isNot(other: ObjectIdentifier | string): boolean {
        return !this.is(other)
    }

    get friendlyName(): string {
        return OIDs.getOidFriendlyName(this.value) || this.value
    }
}
