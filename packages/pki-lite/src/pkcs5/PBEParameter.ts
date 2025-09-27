import { OctetString } from '../asn1/OctetString.js'
import { Asn1BaseBlock, PkiBase, asn1js } from '../core/PkiBase.js'

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
        return new asn1js.Sequence({
            value: [
                this.salt.toAsn1(),
                new asn1js.Integer({ value: this.iterationCount }),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PBEParameter {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Error(
                'Invalid ASN.1 structure: expected Sequence but got ' +
                    asn1.constructor.name,
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 2) {
            throw new Error(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        const saltAsn1 = values[0]
        const iterationCountAsn1 = values[1]

        if (!(saltAsn1 instanceof asn1js.OctetString)) {
            throw new Error(
                'Invalid ASN.1 structure: expected OctetString for salt',
            )
        }

        if (!(iterationCountAsn1 instanceof asn1js.Integer)) {
            throw new Error(
                'Invalid ASN.1 structure: expected Integer for iterationCount',
            )
        }

        return new PBEParameter({
            salt: saltAsn1.valueBlock.valueHexView,
            iterationCount: iterationCountAsn1.valueBlock.valueDec,
        })
    }
}
