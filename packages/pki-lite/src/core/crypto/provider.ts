import { CryptoProvider } from './types.js'
import { WebCryptoProvider } from './WebCryptoProvider.js'

declare global {
    var cryptoProvider: CryptoProvider | null
}

/**
 * Sets the global cryptographic provider for the library.
 *
 * This function allows you to configure which cryptographic implementation
 * the library should use. By default, the library uses WebCryptoProvider
 * which leverages the browser's Web Crypto API. You can replace it with
 * an extended provider that supports additional algorithms.
 *
 * @param newProvider The cryptographic provider to use
 *
 * @example
 * ```typescript
 * import { setCryptoProvider } from 'pki-lite/core/crypto/crypto'
 * import { ExtendedCryptoProvider } from 'pki-lite-crypto-extended'
 *
 * // Use extended crypto provider for legacy algorithm support
 * setCryptoProvider(new ExtendedCryptoProvider())
 *
 * // Now you can use algorithms like MD5, 3DES, etc.
 * const md5Hash = await getCryptoProvider().digest(data, 'MD5')
 * ```
 */
export function setCryptoProvider(newProvider: CryptoProvider) {
    globalThis.cryptoProvider = newProvider
}

/**
 * Gets the current global cryptographic provider.
 *
 * If no provider has been explicitly set, this function returns a default
 * WebCryptoProvider instance. The provider is cached globally for performance
 * and consistency across the library.
 *
 * @returns The current cryptographic provider
 *
 * @example
 * ```typescript
 * import { getCryptoProvider } from 'pki-lite/core/crypto/crypto'
 *
 * // Get the current provider
 * const provider = getCryptoProvider()
 *
 * // Use it for cryptographic operations
 * const hash = await provider.digest(data, 'SHA-256')
 * const signature = await provider.sign(data, privateKey, algorithm)
 * ```
 */
export function getCryptoProvider(): CryptoProvider {
    if (!globalThis.cryptoProvider) {
        globalThis.cryptoProvider = new WebCryptoProvider()
    }

    return globalThis.cryptoProvider
}
