import { CryptoProvider } from './types.js'
import { WebCryptoProvider } from './WebCryptoProvider.js'

declare global {
    var cryptoProvider: CryptoProvider | null
}

export function setCryptoProvider(newProvider: CryptoProvider) {
    globalThis.cryptoProvider = newProvider
}

export function getCryptoProvider(): CryptoProvider {
    if (!globalThis.cryptoProvider) {
        globalThis.cryptoProvider = new WebCryptoProvider()
    }

    return globalThis.cryptoProvider
}
