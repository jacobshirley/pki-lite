import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { EncapsulatedContentInfo } from './EncapsulatedContentInfo.js'

/**
 * Represents a PKCS#7 DigestedData structure.
 *
 * @asn
 * ```asn
 * DigestedData ::= SEQUENCE {
 *      version INTEGER,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      encapContentInfo EncapsulatedContentInfo,
 *      digest Digest
 * }
 * ```
 */
export class DigestedData extends PkiBase<DigestedData> {
    version: number
    digestAlgorithm: AlgorithmIdentifier
    encapContentInfo: EncapsulatedContentInfo
    digest: Uint8Array<ArrayBuffer>

    constructor(options: {
        version: number
        digestAlgorithm: AlgorithmIdentifier
        encapContentInfo: EncapsulatedContentInfo
        digest: Uint8Array<ArrayBuffer>
    }) {
        super()
        const { version, digestAlgorithm, encapContentInfo, digest } = options

        this.version = version
        this.digestAlgorithm = digestAlgorithm
        this.encapContentInfo = encapContentInfo
        this.digest = digest
    }

    /**
     * Converts the DigestedData to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: this.version }),
                this.digestAlgorithm.toAsn1(),
                this.encapContentInfo.toAsn1(),
                new asn1js.OctetString({ valueHex: this.digest }),
            ],
        })
    }
}
