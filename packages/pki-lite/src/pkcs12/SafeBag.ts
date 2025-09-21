import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Attribute } from '../x509/Attribute.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    ObjectIdentifierString,
    derToAsn1,
    ParseableAsn1,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { OIDs } from '../core/OIDs.js'

/**
 * Represents a SafeBag structure in a PKCS#12 file.
 *
 * @asn
 * ```asn
 * SafeBag ::= SEQUENCE {
 *   bagId         BAG-TYPE.
 *   bagValue      [0] EXPLICIT ANY DEFINED BY bagId,
 *   bagAttributes SET OF PKCS12Attribute OPTIONAL
 * }
 * ```
 */
export class SafeBag extends PkiBase<SafeBag> {
    bagId: ObjectIdentifier
    bagValue: Any
    bagAttributes?: Attribute[]

    constructor(options: {
        bagId: ObjectIdentifierString
        bagValue: Asn1Any
        bagAttributes?: Attribute[]
    }) {
        super()
        this.bagId = new ObjectIdentifier({ value: options.bagId })
        this.bagValue = new Any({ derBytes: options.bagValue })
        this.bagAttributes = options.bagAttributes
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            this.bagId.toAsn1(),
            new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 },
                value: [this.bagValue.toAsn1()],
            }),
        ]

        if (this.bagAttributes && this.bagAttributes.length > 0) {
            values.push(
                new asn1js.Set({
                    value: this.bagAttributes.map((a) => a.toAsn1()),
                }),
            )
        }

        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): SafeBag {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'SafeBag: expected SEQUENCE but got ' + asn1.constructor.name,
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 2 || values.length > 3) {
            throw new Asn1ParseError('SafeBag: expected 2 or 3 elements')
        }
        const id = values[0]
        const bagVal = values[1]
        if (!(id instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError('SafeBag: bagId must be OBJECT IDENTIFIER')
        }
        if (
            !(bagVal instanceof asn1js.Constructed) ||
            bagVal.idBlock.tagClass !== 3 ||
            bagVal.idBlock.tagNumber !== 0 ||
            bagVal.valueBlock.value.length !== 1
        ) {
            throw new Asn1ParseError(
                'SafeBag: bagValue must be [0] EXPLICIT with single element',
            )
        }

        let attrs: Attribute[] | undefined
        if (values.length === 3) {
            const set = values[2]
            if (!(set instanceof asn1js.Set)) {
                throw new Asn1ParseError('SafeBag: bagAttributes must be SET')
            }
            attrs = set.valueBlock.value.map((x) => Attribute.fromAsn1(x))
        }

        return new SafeBag({
            bagId: id.valueBlock.toString(),
            bagValue: new Any({ derBytes: bagVal.valueBlock.value[0] }),
            bagAttributes: attrs,
        })
    }

    static fromDer(der: Uint8Array): SafeBag {
        return SafeBag.fromAsn1(derToAsn1(der))
    }

    is(type: keyof typeof OIDs.PKCS12.BAGS): boolean {
        const oid = OIDs.PKCS12.BAGS[type]
        return this.bagId.is(oid)
    }

    isOid(oid: string): boolean {
        return this.bagId.is(oid)
    }

    getAs<T>(parseable: ParseableAsn1<T>): T {
        return this.bagValue.parseAs(parseable)
    }
}
