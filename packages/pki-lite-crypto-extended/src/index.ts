import { setCryptoProvider } from 'pki-lite/core/crypto/provider.js'
import { WebCryptoExtendedProvider } from './crypto/WebCryptoExtendedProvider.js'

setCryptoProvider(new WebCryptoExtendedProvider())

export { WebCryptoExtendedProvider }
export * from './crypto/types.js'
