import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Asn1Any, Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'

/**
 * Represents the OtherRevInfo structure used in RevocationInfoArchival.
 *
 * @asn
 * ```asn
 * OtherRevInfo ::= SEQUENCE {
 *   Type  OBJECT IDENTIFIER
 *   Value OCTET STRING
 * }
 * ```
 */
export class OtherRevInfo extends PkiBase<OtherRevInfo> {
    type: ObjectIdentifier
    value: Any

    constructor(options: { type: string; value: Asn1Any }) {
        super()
        this.type = new ObjectIdentifier({ value: options.type })
        this.value = new Any({ derBytes: options.value })
    }

    toAsn1(): asn1js.Sequence {
        return new asn1js.Sequence({
            value: [this.type.toAsn1(), this.value.toAsn1()],
        })
    }

    static fromAsn1(asn1: asn1js.Sequence): OtherRevInfo {
        const type = asn1.valueBlock.value[0] as asn1js.ObjectIdentifier
        const value = asn1.valueBlock.value[1]

        return new OtherRevInfo({
            type: type.valueBlock.toString(),
            value: new Any({ derBytes: value }),
        })
    }
}
