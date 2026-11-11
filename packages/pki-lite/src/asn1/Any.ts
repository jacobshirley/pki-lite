import {
    Asn1Node,
    asn1ToDer,
    der,
    derToAsn1,
    ParseableAsn1,
    PkiBase,
    TagClass,
    UniversalTag,
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
            | Asn1Node
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
            this.derBytes = asn1ToDer(der.boolean(derBytes))
        } else if (derBytes === null) {
            this.derBytes = null
        } else if (derBytes instanceof Asn1Node) {
            this.derBytes = asn1ToDer(derBytes)
        } else if (typeof derBytes === 'string') {
            // PrintableString when the characters allow it, UTF8String otherwise
            this.derBytes = asn1ToDer(
                isPrintable(derBytes)
                    ? der.printableString(derBytes)
                    : der.utf8String(derBytes),
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

    toAsn1(): Asn1Node {
        if (this.derBytes === null) {
            return der.nullValue()
        }
        return derToAsn1(this.derBytes)
    }

    /**
     * Returns the value as a string: character strings are decoded, OCTET STRING
     * content is read as UTF-8, anything else gives its ASN.1 dump.
     */
    asString(): string {
        const asn1 = this.toAsn1()
        if (asn1.is(UniversalTag.OctetString)) {
            return new TextDecoder().decode(asn1.bytes())
        }
        return readCharacterString(asn1) ?? asn1.toString()
    }

    asInteger(): number {
        return this.parseAs(Integer).get()
    }

    toHumanString(): string {
        if (this.derBytes === null) {
            return 'NULL'
        }

        const asn1 = this.toAsn1()
        const text = readCharacterString(asn1)
        if (text !== undefined) {
            return text
        }
        if (asn1.tagClass !== TagClass.Universal) {
            return asn1.toString()
        }

        switch (asn1.tag) {
            case UniversalTag.OctetString:
                return new TextDecoder().decode(asn1.bytes())
            case UniversalTag.Integer:
                return der.readBigInt(asn1).toString()
            case UniversalTag.ObjectIdentifier:
                return der.readOid(asn1)
            case UniversalTag.Boolean:
                return der.readBoolean(asn1) ? 'TRUE' : 'FALSE'
            case UniversalTag.Null:
                return 'NULL'
            case UniversalTag.BitString: {
                const { bytes, unusedBits } = der.readBitString(asn1)
                return `BIT STRING (${bytes.length * 8 - unusedBits} bits)`
            }
            case UniversalTag.UTCTime:
            case UniversalTag.GeneralizedTime:
                return der.readTime(asn1).toISOString()
            case UniversalTag.Sequence:
                return `SEQUENCE (${asn1.children.length} items)`
            case UniversalTag.Set:
                return `SET (${asn1.children.length} items)`
        }
        return asn1.toString()
    }

    static fromAsn1(asn1: Asn1Node): Any {
        return new Any({ derBytes: asn1ToDer(asn1) })
    }

    static fromDer(derBytes: Uint8Array<ArrayBuffer> | ArrayBuffer): Any {
        return new Any({ derBytes })
    }
}

const characterStringTags: readonly number[] = [
    UniversalTag.UTF8String,
    UniversalTag.PrintableString,
    UniversalTag.TeletexString,
    UniversalTag.IA5String,
    UniversalTag.VisibleString,
    UniversalTag.UniversalString,
    UniversalTag.BMPString,
]

function readCharacterString(asn1: Asn1Node): string | undefined {
    return asn1.tagClass === TagClass.Universal &&
        characterStringTags.includes(asn1.tag)
        ? der.readString(asn1)
        : undefined
}

const isPrintable = (value: string) => /^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)
