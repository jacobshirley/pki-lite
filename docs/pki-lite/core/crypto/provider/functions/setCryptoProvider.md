[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/provider](../README.md) / setCryptoProvider

# Function: setCryptoProvider()

> **setCryptoProvider**(`newProvider`): `void`

Sets the global cryptographic provider for the library.

This function allows you to configure which cryptographic implementation
the library should use. By default, the library uses WebCryptoProvider
which leverages the browser's Web Crypto API. You can replace it with
an extended provider that supports additional algorithms.

## Parameters

### newProvider

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md)

The cryptographic provider to use

## Returns

`void`

## Example

```typescript
import { setCryptoProvider } from 'pki-lite/core/crypto/crypto'
import { ExtendedCryptoProvider } from 'pki-lite-crypto-extended'

// Use extended crypto provider for legacy algorithm support
setCryptoProvider(new ExtendedCryptoProvider())

// Now you can use algorithms like MD5, 3DES, etc.
const md5Hash = await getCryptoProvider().digest(data, 'MD5')
```
