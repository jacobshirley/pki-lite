import {
    Asn1BaseBlock,
    asn1js,
    asn1ToDer,
    derToAsn1,
    ParseableAsn1,
    PkiBase,
} from '../core/PkiBase.js'
import { Integer } from './Integer.js'

/**
 * Represents an ASN.1 ANY value.
 *
 * @asn
 * ```asn
 * ANY ::= <value>
 * ```
 */
export class Any extends PkiBase<Any> {
    derBytes: Uint8Array<ArrayBuffer> | null

    constructor(options: {
        derBytes:
            | Uint8Array<ArrayBuffer>
            | ArrayBuffer
            | Asn1BaseBlock
            | null
            | string
            | Any
            | PkiBase
            | number
            | boolean
    }) {
        super()
        const { derBytes } = options

        if (typeof derBytes === 'boolean') {
            this.derBytes = asn1ToDer(new asn1js.Boolean({ value: derBytes }))
        } else if (derBytes === null) {
            this.derBytes = null
        } else if (derBytes instanceof asn1js.BaseBlock) {
            this.derBytes = asn1ToDer(derBytes)
        } else if (typeof derBytes === 'string') {
            this.derBytes = asn1ToDer(
                new asn1js.PrintableString({
                    value: derBytes,
                }),
            )
        } else if (typeof derBytes === 'number') {
            this.derBytes = new Integer({ value: derBytes }).toDer()
        } else if (derBytes instanceof Any) {
            this.derBytes = derBytes.derBytes
        } else if (derBytes instanceof PkiBase) {
            this.derBytes = derBytes.toDer()
        } else {
            this.derBytes = new Uint8Array(derBytes)
        }
    }

    toAsn1(): Asn1BaseBlock {
        if (this.derBytes === null) {
            return new asn1js.Null()
        }
        return derToAsn1(this.derBytes)
    }

    asString(): string {
        const asn1 = this.toAsn1()
        if (asn1 instanceof asn1js.PrintableString) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.Utf8String) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.OctetString) {
            return new TextDecoder().decode(asn1.valueBlock.valueHexView)
        } else if (asn1 instanceof asn1js.TeletexString) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.BmpString) {
            return asn1.getValue()
        }
        return asn1.toString()
    }

    asInteger(): number {
        return this.parseAs(Integer).get()
    }

    toHumanString(): string {
        if (this.derBytes === null) {
            return 'NULL'
        }

        const asn1 = this.toAsn1()
        if (asn1 instanceof asn1js.PrintableString) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.Utf8String) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.OctetString) {
            return new TextDecoder().decode(asn1.valueBlock.valueHexView)
        } else if (asn1 instanceof asn1js.TeletexString) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.BmpString) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.Integer) {
            return asn1.valueBlock.valueDec.toString()
        } else if (asn1 instanceof asn1js.ObjectIdentifier) {
            return asn1.valueBlock.toString()
        } else if (asn1 instanceof asn1js.Boolean) {
            return asn1.valueBlock.value ? 'TRUE' : 'FALSE'
        } else if (asn1 instanceof asn1js.Null) {
            return 'NULL'
        } else if (asn1 instanceof asn1js.BitString) {
            return `BIT STRING (${asn1.valueBlock.valueBeforeDecodeView.byteLength * 8} bits)`
        } else if (asn1 instanceof asn1js.IA5String) {
            return asn1.getValue()
        } else if (asn1 instanceof asn1js.GeneralizedTime) {
            return asn1.toString()
        } else if (asn1 instanceof asn1js.UTCTime) {
            return asn1.toString()
        } else if (asn1 instanceof asn1js.Sequence) {
            return `SEQUENCE (${asn1.valueBlock.value.length} items)`
        } else if (asn1 instanceof asn1js.Set) {
            return `SET (${asn1.valueBlock.value.length} items)`
        }
        return asn1.toString()
    }

    static fromAsn1(asn1: Asn1BaseBlock): Any {
        return new Any({ derBytes: asn1ToDer(asn1) })
    }

    static fromDer(derBytes: Uint8Array<ArrayBuffer> | ArrayBuffer): Any {
        return new Any({ derBytes })
    }
}
