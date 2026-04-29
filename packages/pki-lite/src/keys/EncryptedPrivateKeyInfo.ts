import { ContentEncryptionAlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { asn1js, PkiBase } from '../core/PkiBase.js'
import { PrivateKeyInfo } from './PrivateKeyInfo.js'

/**
 * Represents an EncryptedPrivateKeyInfo structure in a PKCS#12 file.
 *
 * @asn
 * ```asn
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *   encryptedData        EncryptedData
 * }
 *
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedData ::= OCTET STRING
 * ```
 */
export class EncryptedPrivateKeyInfo extends PkiBase<EncryptedPrivateKeyInfo> {
    encryptionAlgorithm: ContentEncryptionAlgorithmIdentifier
    encryptedData: OctetString

    constructor(options: {
        encryptionAlgorithm: ContentEncryptionAlgorithmIdentifier
        encryptedData: OctetString | Uint8Array<ArrayBuffer>
    }) {
        super()
        this.encryptionAlgorithm = options.encryptionAlgorithm
        this.encryptedData = new OctetString({
            bytes: options.encryptedData,
        })
    }

    toAsn1() {
        return new asn1js.Sequence({
            value: [
                this.encryptionAlgorithm.toAsn1(),
                this.encryptedData.toAsn1(),
            ],
        })
    }

    static fromAsn1(asn1: asn1js.BaseBlock): EncryptedPrivateKeyInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Error('EncryptedPrivateKeyInfo: expected SEQUENCE')
        }

        const [alg, data] = asn1.valueBlock.value
        return new EncryptedPrivateKeyInfo({
            encryptionAlgorithm:
                ContentEncryptionAlgorithmIdentifier.fromAsn1(alg),
            encryptedData: OctetString.fromAsn1(data),
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): EncryptedPrivateKeyInfo {
        return EncryptedPrivateKeyInfo.fromAsn1(asn1js.fromBER(der).result)
    }

    /**
     * Creates an encrypted private key using PBES2 (PBKDF2 + AES-256-CBC).
     *
     * @param privateKey The private key to encrypt
     * @param password The password (string or bytes)
     * @param options Optional parameters for encryption
     * @returns Promise resolving to the encrypted private key
     */
    static async create(
        privateKey: PrivateKeyInfo,
        password: string | Uint8Array<ArrayBuffer>,
        options?: {
            salt?: Uint8Array<ArrayBuffer>
            iv?: Uint8Array<ArrayBuffer>
            iterations?: number
        },
    ): Promise<EncryptedPrivateKeyInfo> {
        const salt = options?.salt ?? crypto.getRandomValues(new Uint8Array(16))
        const iv = options?.iv ?? crypto.getRandomValues(new Uint8Array(16))
        const iterations = options?.iterations ?? 2048

        const algorithm = AlgorithmIdentifier.contentEncryptionAlgorithm({
            type: 'PBES2',
            params: {
                derivationAlgorithm: {
                    type: 'PBKDF2',
                    params: {
                        salt,
                        iterationCount: iterations,
                        hash: 'SHA-256',
                    },
                },
                encryptionAlgorithm: {
                    type: 'AES_256_CBC',
                    params: { nonce: iv },
                },
            },
        })

        const encryptedData = await algorithm.encrypt(
            privateKey.toDer(),
            password,
        )

        return new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })
    }

    async decrypt(
        key: Uint8Array<ArrayBuffer> | string,
    ): Promise<PrivateKeyInfo> {
        if (typeof key === 'string') {
            key = new TextEncoder().encode(key)
        }
        const decrypted = await this.encryptionAlgorithm.decrypt(
            this.encryptedData.bytes,
            key,
        )
        return PrivateKeyInfo.fromDer(decrypted)
    }

    get pemHeader(): string {
        return 'ENCRYPTED PRIVATE KEY'
    }
}
