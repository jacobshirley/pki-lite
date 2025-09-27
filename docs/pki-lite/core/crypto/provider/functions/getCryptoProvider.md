[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/provider](../README.md) / getCryptoProvider

# Function: getCryptoProvider()

> **getCryptoProvider**(): [`CryptoProvider`](../../types/interfaces/CryptoProvider.md)

Gets the current global cryptographic provider.

If no provider has been explicitly set, this function returns a default
WebCryptoProvider instance. The provider is cached globally for performance
and consistency across the library.

## Returns

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md)

The current cryptographic provider

## Example

```typescript
import { getCryptoProvider } from 'pki-lite/core/crypto/crypto'

// Get the current provider
const provider = getCryptoProvider()

// Use it for cryptographic operations
const hash = await provider.digest(data, 'SHA-256')
const signature = await provider.sign(data, privateKey, algorithm)
```
