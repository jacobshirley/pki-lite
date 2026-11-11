import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Asn1Any, Asn1Node, der, PkiBase } from '../core/PkiBase.js'

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

    toAsn1(): Asn1Node {
        return der.sequence([this.type.toAsn1(), this.value.toAsn1()])
    }

    static fromAsn1(asn1: Asn1Node): OtherRevInfo {
        const type = asn1.children[0]
        const value = asn1.children[1]

        return new OtherRevInfo({
            type: der.readOid(type),
            value: new Any({ derBytes: value }),
        })
    }
}
