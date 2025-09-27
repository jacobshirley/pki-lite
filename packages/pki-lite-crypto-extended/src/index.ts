import { setCryptoProvider } from 'pki-lite/core/crypto/provider.js'
import { WebCryptoExtendedProvider } from './crypto/WebCryptoExtendedProvider'

setCryptoProvider(new WebCryptoExtendedProvider())

export { WebCryptoExtendedProvider }
export * from './crypto/types.js'
