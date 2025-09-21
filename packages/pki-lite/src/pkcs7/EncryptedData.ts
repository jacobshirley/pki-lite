import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { EncryptedContentInfo } from './EncryptedContentInfo.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a PKCS#7 EncryptedData structure.
 *
 * @asn
 * ```asn
 * EncryptedData ::= SEQUENCE {
 *      version INTEGER,
 *      encryptedContentInfo EncryptedContentInfo
 *      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 * ```
 */
export class EncryptedData extends PkiBase<EncryptedData> {
    version: number
    encryptedContentInfo: EncryptedContentInfo

    constructor(options: {
        version: number
        encryptedContentInfo: EncryptedContentInfo
    }) {
        super()
        const { version, encryptedContentInfo } = options

        this.version = version
        this.encryptedContentInfo = encryptedContentInfo
    }

    /**
     * Converts the EncryptedData to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: this.version }),
                this.encryptedContentInfo.toAsn1(),
            ],
        })
    }

    /**
     * Creates an EncryptedData from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): EncryptedData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 2) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected 2 elements, got ${values.length}`,
            )
        }

        // Version
        if (!(values[0] instanceof asn1js.Integer)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Integer for version',
            )
        }
        const version = values[0].valueBlock.valueDec

        // EncryptedContentInfo
        const encryptedContentInfo = EncryptedContentInfo.fromAsn1(values[1])

        return new EncryptedData({ version, encryptedContentInfo })
    }
}
