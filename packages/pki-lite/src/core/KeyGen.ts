import { PrivateKeyInfo } from '../keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { getCryptoProvider } from './crypto/provider.js'
import { KeyPair, KeyPairGenOptions } from './crypto/types.js'

/**
 * KeyGen class provides functionality to generate cryptographic key pairs.
 *
 * This class leverages the configured cryptographic provider to create
 * key pairs for various algorithms such as RSA, ECDSA, and EdDSA. The
 * generated keys are returned in standard formats suitable for storage
 * and usage in cryptographic operations.
 *
 * @example
 * ```typescript
 * // Generate an RSA key pair
 * const { privateKey, publicKey } = await KeyGen.generate({
 *     algorithm: 'RSA',
 *     params: {
 *         modulusLength: 2048,
 *         publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
 *         hash: 'SHA-256'
 *     }
 * })
 */
export class KeyGen {
    /**
     * Generates a new key pair.
     *
     * @param options The key generation options
     * @returns A PrivateKeyInfo containing the generated key pair
     *
     * @example
     * ```typescript
     * // Generate an ECDSA key pair using P-256 curve
     * const { privateKey, publicKey } = await KeyGen.generate({
     *     algorithm: 'ECDSA',
     *     params: {
     *         namedCurve: 'P-256',
     *         hash: 'SHA-256'
     *     }
     * })
     */
    static async generate(options: KeyPairGenOptions): Promise<{
        privateKey: PrivateKeyInfo
        publicKey: SubjectPublicKeyInfo
    }> {
        const keyPair: KeyPair =
            await getCryptoProvider().generateKeyPair(options)

        const privateKey = PrivateKeyInfo.fromDer(keyPair.privateKey)
        const publicKey = SubjectPublicKeyInfo.fromDer(keyPair.publicKey)

        return { privateKey, publicKey }
    }
}
