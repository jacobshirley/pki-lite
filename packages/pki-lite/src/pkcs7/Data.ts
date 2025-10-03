import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'

/**
 * Represents PKCS#7 Data content.
 *
 * This is the simplest form of content in PKCS#7, representing raw data.
 *
 * @asn
 * ```asn
 * Data ::= OCTET STRING
 * ```
 */
export class Data extends PkiBase<Data> {
    data: Uint8Array<ArrayBuffer>

    constructor(options: { data: Uint8Array<ArrayBuffer> }) {
        super()
        const { data } = options
        this.data = data
    }

    /**
     * Converts the Data to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.OctetString({ valueHex: this.data })
    }
}
