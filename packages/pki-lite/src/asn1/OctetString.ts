import {
    Asn1Node,
    der,
    derToAsn1,
    TagClass,
    UniversalTag,
    ParseableAsn1,
    PkiArray,
    PkiBase,
    PkiSequence,
    PkiSet,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents an ASN.1 OCTET STRING value.
 *
 * @asn
 * ```asn
 * OctetString ::= <value>
 * ```
 */
export class OctetString extends PkiBase<OctetString> {
    bytes: Uint8Array<ArrayBuffer>

    constructor(options: {
        bytes:
            | string
            | Uint8Array
            | OctetString
            | PkiBase
            | PkiSequence
            | PkiSet
    }) {
        super()
        const { bytes } = options
        if (bytes instanceof OctetString) {
            this.bytes = bytes.bytes
        } else if (typeof bytes === 'string') {
            this.bytes = new TextEncoder().encode(bytes)
        } else if (
            bytes instanceof PkiBase ||
            bytes instanceof PkiSequence ||
            bytes instanceof PkiSet
        ) {
            this.bytes = bytes.toDer()
        } else {
            this.bytes = new Uint8Array(bytes)
        }
    }

    toAsn1(): Asn1Node {
        return der.octetString(this.bytes)
    }

    toUint8Array(): Uint8Array<ArrayBuffer> {
        return this.bytes
    }

    static fromAsn1(asn1: Asn1Node): OctetString {
        // Also accepts an implicitly tagged primitive, e.g. `[0] IMPLICIT OCTET STRING`
        if (
            !asn1.is(UniversalTag.OctetString) &&
            (asn1.tagClass === TagClass.Universal || asn1.constructed)
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OCTET STRING but got ' +
                    asn1.describe(),
            )
        }

        return new OctetString({ bytes: asn1.bytes() })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): OctetString {
        return OctetString.fromAsn1(derToAsn1(der))
    }

    parseAs<T>(type: ParseableAsn1<T>): T {
        if (type.fromDer) {
            return type.fromDer(this.bytes)
        } else if (type.fromAsn1) {
            return type.fromAsn1(derToAsn1(this.bytes))
        } else {
            throw new Asn1ParseError(
                'Invalid type: must implement fromAsn1 or fromDer',
            )
        }
    }
}
