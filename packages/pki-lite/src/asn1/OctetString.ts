import {
    Asn1BaseBlock,
    asn1js,
    derToAsn1,
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

    toAsn1(): Asn1BaseBlock {
        return new asn1js.OctetString({ valueHex: this.bytes })
    }

    toUint8Array(): Uint8Array<ArrayBuffer> {
        return this.bytes
    }

    static fromAsn1(asn1: Asn1BaseBlock): OctetString {
        if (
            !(asn1 instanceof asn1js.OctetString) &&
            !(asn1 instanceof asn1js.Primitive)
        ) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected OCTET STRING but got ' +
                    asn1.constructor.name,
            )
        }

        return new OctetString({ bytes: OctetString.contentBytes(asn1) })
    }

    /**
     * The value bytes of an OCTET STRING. BER allows a *constructed* encoding (what
     * indefinite-length streaming writers such as `openssl cms -stream` produce): a
     * sequence of OCTET STRING chunks whose contents are concatenated.
     */
    static contentBytes(asn1: Asn1BaseBlock): Uint8Array {
        if (asn1.idBlock.isConstructed) {
            const chunks = (asn1.valueBlock as { value?: Asn1BaseBlock[] })
                .value
            if (chunks && chunks.length > 0) {
                const parts = chunks.map((chunk) =>
                    OctetString.contentBytes(chunk),
                )
                const out = new Uint8Array(
                    parts.reduce((total, part) => total + part.length, 0),
                )
                let offset = 0
                for (const part of parts) {
                    out.set(part, offset)
                    offset += part.length
                }
                return out
            }
        }
        return (asn1 as asn1js.Primitive).valueBlock.valueHexView
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
