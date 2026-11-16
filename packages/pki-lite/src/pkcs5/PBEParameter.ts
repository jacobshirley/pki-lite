import { OctetString } from '../asn1/OctetString.js'
import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'

/**
 * PBEParameter ASN.1 structure
 *
 * @asn
 * ```asn
 * PBEParameter ::= SEQUENCE {
 *     salt OCTET STRING (8 bytes),
 *     iterationCount INTEGER
 * }
 * ```
 */
export class PBEParameter extends PkiBase<PBEParameter> {
    salt: OctetString
    iterationCount: number

    constructor(options: { salt: Uint8Array; iterationCount: number }) {
        super()
        this.salt = new OctetString({ bytes: options.salt })
        this.iterationCount = options.iterationCount
    }

    toAsn1() {
        return der.sequence([
            this.salt.toAsn1(),
            der.integer(this.iterationCount),
        ])
    }

    static fromAsn1(asn1: Asn1Node): PBEParameter {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Error(
                'Invalid ASN.1 structure: expected Sequence but got ' +
                    asn1.describe(),
            )
        }

        const values = asn1.children
        if (values.length !== 2) {
            throw new Error(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        const saltAsn1 = values[0]
        const iterationCountAsn1 = values[1]

        if (!saltAsn1.is(UniversalTag.OctetString)) {
            throw new Error(
                'Invalid ASN.1 structure: expected OctetString for salt',
            )
        }

        if (!iterationCountAsn1.is(UniversalTag.Integer)) {
            throw new Error(
                'Invalid ASN.1 structure: expected Integer for iterationCount',
            )
        }

        return new PBEParameter({
            salt: saltAsn1.bytes(),
            iterationCount: der.readNumber(iterationCountAsn1),
        })
    }
}
