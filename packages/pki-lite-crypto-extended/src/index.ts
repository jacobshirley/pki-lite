import { setCryptoProvider } from 'pki-lite/core/crypto/crypto'
import { WebCryptoExtendedProvider } from './WebCryptoExtendedProvider'

setCryptoProvider(new WebCryptoExtendedProvider())

export { WebCryptoExtendedProvider }
