import { OctetString } from '../asn1/OctetString.js'
import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'
import { DigestInfo } from './DigestInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { BMPString } from '../asn1/BMPString.js'
import { pkcs12Derive } from '../core/crypto/utils.js'
import type { HashAlgorithm } from '../core/crypto/types.js'

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
        macSalt: OctetString | Uint8Array<ArrayBuffer>
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

    static fromDer(der: Uint8Array<ArrayBuffer>): MacData {
        return MacData.fromAsn1(derToAsn1(der))
    }

    /**
     * Creates a PKCS#12 MacData: HMAC over `data` keyed by a key
     * derived using the PKCS#12 password-based KDF (RFC 7292 Appendix B).
     *
     * Note: Uses the legacy PKCS#12 KDF for MAC key derivation to maintain
     * compatibility with OpenSSL and other PKCS#12 implementations.
     *
     * @param data The data to compute MAC over
     * @param password The password (string or bytes)
     * @param iterations Iteration count for KDF
     * @param hash Hash algorithm to use (default: SHA-256)
     * @returns Promise resolving to MacData instance
     */
    static async create(
        data: Uint8Array<ArrayBuffer>,
        password: string | Uint8Array<ArrayBuffer>,
        iterations: number,
        hash: HashAlgorithm = 'SHA-256',
    ): Promise<MacData> {
        const macSalt = crypto.getRandomValues(new Uint8Array(8))
        const passwordBytes = BMPString.nullTerminated(password)
        const digestAlgorithm = AlgorithmIdentifier.digestAlgorithm(hash)
        const keyLen = digestAlgorithm.getOutputBytes()

        // Use PKCS#12 KDF (RFC 7292 Appendix B) for MAC key derivation
        // This is required for OpenSSL compatibility
        const macKey = await pkcs12Derive(
            passwordBytes,
            macSalt,
            3 /* MAC key */,
            iterations,
            keyLen,
            hash,
        )

        const macValue = await digestAlgorithm.hmac(macKey, data)

        return new MacData({
            mac: new DigestInfo({
                digestAlgorithm,
                digest: new OctetString({ bytes: macValue }),
            }),
            macSalt: new OctetString({ bytes: macSalt }),
            iterations,
        })
    }
}
