import { OctetString } from '../asn1/OctetString.js'
import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { DigestInfo } from './DigestInfo.js'

/**
 * Represents a MacData structure in a PKCS#12 file.
 *
 * @asn
 * ```asn
 * MacData ::= SEQUENCE {
 *    mac        DigestInfo,
 *    macSalt    OCTET STRING,
 *    iterations INTEGER DEFAULT 1
 * }
 * ```
 */
export class MacData extends PkiBase<MacData> {
    mac: DigestInfo
    macSalt: OctetString
    iterations: number

    constructor(options: {
        mac: DigestInfo
        macSalt: OctetString | Uint8Array
        iterations?: number
    }) {
        super()
        this.mac = options.mac
        this.macSalt =
            options.macSalt instanceof OctetString
                ? options.macSalt
                : new OctetString({ bytes: options.macSalt })
        this.iterations = options.iterations ?? 1
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [
            this.mac.toAsn1(),
            this.macSalt.toAsn1(),
        ]
        if (this.iterations !== 1) {
            values.push(new asn1js.Integer({ value: this.iterations }))
        }
        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): MacData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError('MacData: expected SEQUENCE')
        }
        const values = asn1.valueBlock.value
        if (values.length < 2 || values.length > 3) {
            throw new Asn1ParseError('MacData: expected 2 or 3 elements')
        }
        const mac = DigestInfo.fromAsn1(values[0])
        const macSalt = OctetString.fromAsn1(values[1])
        let iterations = 1
        if (values.length === 3) {
            const it = values[2]
            if (!(it instanceof asn1js.Integer)) {
                throw new Asn1ParseError('MacData: iterations must be INTEGER')
            }
            iterations = it.valueBlock.valueDec
        }
        return new MacData({ mac, macSalt, iterations })
    }

    static fromDer(der: Uint8Array): MacData {
        return MacData.fromAsn1(derToAsn1(der))
    }
}
