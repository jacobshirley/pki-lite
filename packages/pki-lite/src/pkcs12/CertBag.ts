import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import {
    Asn1BaseBlock,
    asn1js,
    PkiBase,
    Asn1Any,
    ObjectIdentifierString,
    derToAsn1,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a CertBag structure in a PKCS#12 file.
 *
 * @asn
 * ```asn
 * CertBag ::= SEQUENCE {
 *   certId    BAG-TYPE.
 *   certValue [0] EXPLICIT ANY DEFINED BY certId
 * }
 * ```
 */
export class CertBag extends PkiBase<CertBag> {
    certId: ObjectIdentifier
    certValue: Any

    constructor(options: {
        certId: ObjectIdentifierString
        certValue: Asn1Any
    }) {
        super()
        this.certId = new ObjectIdentifier({ value: options.certId })
        this.certValue = new Any({ derBytes: options.certValue })
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                this.certId.toAsn1(),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 }, // [0] EXPLICIT
                    value: [this.certValue.toAsn1()],
                }),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): CertBag {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('CertBag: expected SEQUENCE')
        }
        const [id, val] = asn1.valueBlock.value
        if (!(id instanceof asn1js.ObjectIdentifier)) {
            throw new Asn1ParseError(
                'CertBag: certId must be OBJECT IDENTIFIER',
            )
        }
        if (
            !(val instanceof asn1js.Constructed) ||
            val.idBlock.tagClass !== 3 ||
            val.idBlock.tagNumber !== 0 ||
            val.valueBlock.value.length !== 1
        ) {
            throw new Asn1ParseError(
                'CertBag: certValue must be [0] EXPLICIT with single element',
            )
        }
        return new CertBag({
            certId: id.valueBlock.toString(),
            certValue: new Any({ derBytes: val.valueBlock.value[0] }),
        })
    }

    static fromDer(der: Uint8Array): CertBag {
        return CertBag.fromAsn1(derToAsn1(der))
    }
}
