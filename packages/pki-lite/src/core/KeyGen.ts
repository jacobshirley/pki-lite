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
 *         keySize: 2048,
 *         hash: 'SHA-256'
 *     }
 * })
 *
 * // Or use convenience methods
 * const rsaPair = await KeyGen.generateRsaPair({ keySize: 2048 })
 * const ecPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
 * ```
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
     *     algorithm: 'EC',
     *     params: {
     *         namedCurve: 'P-256'
     *     }
     * })
     * ```
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

    /**
     * Generates an RSA key pair with the specified options.
     *
     * @param options RSA key generation options (defaults: keySize=2048, hash='SHA-256')
     * @returns A PrivateKeyInfo containing the generated RSA key pair
     *
     * @example
     * ```typescript
     * // Generate 2048-bit RSA key pair
     * const { privateKey, publicKey } = await KeyGen.generateRsaPair()
     *
     * // Generate 4096-bit RSA key pair with SHA-512
     * const { privateKey, publicKey } = await KeyGen.generateRsaPair({
     *     keySize: 4096,
     *     hash: 'SHA-512'
     * })
     * ```
     */
    static async generateRsaPair(options?: {
        keySize?: number
        publicExponent?: number
        hash?: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
    }): Promise<{
        privateKey: PrivateKeyInfo
        publicKey: SubjectPublicKeyInfo
    }> {
        return KeyGen.generate({
            algorithm: 'RSA',
            params: {
                keySize: 2048,
                hash: 'SHA-256',
                ...options,
            },
        })
    }

    /**
     * Generates an EC (Elliptic Curve) key pair with the specified curve.
     *
     * @param options EC key generation options (defaults: namedCurve='P-256')
     * @returns A PrivateKeyInfo containing the generated EC key pair
     *
     * @example
     * ```typescript
     * // Generate P-256 EC key pair (default)
     * const { privateKey, publicKey } = await KeyGen.generateEcPair()
     *
     * // Generate P-384 EC key pair
     * const { privateKey, publicKey } = await KeyGen.generateEcPair({
     *     namedCurve: 'P-384'
     * })
     * ```
     */
    static async generateEcPair(options?: {
        namedCurve?: 'P-256' | 'P-384' | 'P-521'
    }): Promise<{
        privateKey: PrivateKeyInfo
        publicKey: SubjectPublicKeyInfo
    }> {
        return KeyGen.generate({
            algorithm: 'EC',
            params: {
                namedCurve: 'P-256',
                ...options,
            },
        })
    }
}
