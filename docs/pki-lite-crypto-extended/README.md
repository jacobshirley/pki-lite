[**PKI-Lite v1.0.0**](../README.md)

---

[PKI-Lite](../README.md) / pki-lite-crypto-extended

# pki-lite-crypto-extended

Extended cryptographic provider for [pki-lite](../pki-lite/README.md) that adds support for legacy and specialized cryptographic algorithms.

## Overview

This package extends the base PKI-Lite cryptographic capabilities by adding:

- **MD5 hashing** - Legacy hash algorithm support
- **AES ECB mode** - Electronic Codebook encryption for all AES key sizes
- **AES CBC without padding** - Specialized CBC mode with padding disabled

The extended provider seamlessly integrates with the existing PKI-Lite infrastructure while maintaining full backward compatibility.

## Features

### MD5 Hash Algorithm

- Support for the MD5 hash algorithm using [@noble/hashes](https://github.com/paulmillr/noble-hashes)
- Required for legacy PDF encryption and some older PKI systems
- Produces standard 128-bit (16-byte) hash digests

### AES ECB Encryption

- AES encryption in Electronic Codebook (ECB) mode
- Supports all standard AES key sizes: 128, 192, and 256 bits
- Useful for specific cryptographic protocols that require ECB mode

### AES CBC No-Padding

- AES encryption in Cipher Block Chaining (CBC) mode with padding disabled
- Required for certain legacy systems and specialized protocols
- Supports all standard AES key sizes with custom initialization vectors

### Graceful Fallback

- Automatically falls back to the base WebCryptoProvider for unsupported algorithms
- Maintains full compatibility with existing PKI-Lite cryptographic operations
- No breaking changes to existing code

## Installation

```bash
# Using pnpm (recommended)
pnpm add pki-lite-crypto-extended

# Using npm
npm install pki-lite-crypto-extended

# Using yarn
yarn add pki-lite-crypto-extended
```

## Usage

### Automatic Setup (Recommended)

Simply import the package to automatically enable extended cryptographic capabilities:

```typescript
import 'pki-lite-crypto-extended'

// Extended crypto provider is now active globally
// All PKI-Lite operations now support MD5, AES-ECB, etc.
```

### Manual Setup

For more control, you can manually configure the provider:

```typescript
import { WebCryptoExtendedProvider } from 'pki-lite-crypto-extended'
import { setCryptoProvider } from 'pki-lite/core/crypto/crypto'

// Set up the extended provider
const provider = new WebCryptoExtendedProvider()
setCryptoProvider(provider)
```

### Using MD5 Hashing

```typescript
import { getCryptoProvider } from 'pki-lite/core/crypto/crypto'

const provider = getCryptoProvider()
const data = new TextEncoder().encode('Hello, World!')

// Compute MD5 hash
const md5Hash = await provider.digest(data, 'MD5')
console.log(
    'MD5:',
    Array.from(md5Hash)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(''),
)
```

### Using AES ECB Encryption

```typescript
import { getCryptoProvider } from 'pki-lite/core/crypto/crypto'

const provider = getCryptoProvider()
const key = new Uint8Array(16).fill(0x01) // 128-bit key
const plaintext = new TextEncoder().encode('Secret message!!')

// Encrypt with AES-128-ECB
const ciphertext = await provider.encryptSymmetric(plaintext, key, {
    type: 'AES_128_ECB',
    params: {},
})

// Decrypt
const decrypted = await provider.decryptSymmetric(ciphertext, key, {
    type: 'AES_128_ECB',
    params: {},
})

console.log('Decrypted:', new TextDecoder().decode(decrypted))
```

### Using AES CBC Without Padding

```typescript
import { getCryptoProvider } from 'pki-lite/core/crypto/crypto'

const provider = getCryptoProvider()
const key = new Uint8Array(32).fill(0x01) // 256-bit key
const iv = new Uint8Array(16).fill(0x02) // 128-bit IV
const plaintext = new Uint8Array(16).fill(0x03) // Must be multiple of block size

// Encrypt with AES-256-CBC (no padding)
const ciphertext = await provider.encryptSymmetric(plaintext, key, {
    type: 'AES_256_CBC',
    params: {
        nonce: iv,
        disablePadding: true,
    },
})

// Decrypt
const decrypted = await provider.decryptSymmetric(ciphertext, key, {
    type: 'AES_256_CBC',
    params: {
        nonce: iv,
        disablePadding: true,
    },
})
```

## Supported Algorithms

### Hash Algorithms

| Algorithm                | Description                             | Output Size |
| ------------------------ | --------------------------------------- | ----------- |
| `MD5`                    | Legacy hash function                    | 16 bytes    |
| `SHA-1`, `SHA-256`, etc. | Standard algorithms (via base provider) | Varies      |

### Symmetric Encryption Algorithms

| Algorithm         | Key Sizes | Description                                |
| ----------------- | --------- | ------------------------------------------ |
| `AES_128_ECB`     | 128-bit   | AES Electronic Codebook mode               |
| `AES_192_ECB`     | 192-bit   | AES Electronic Codebook mode               |
| `AES_256_ECB`     | 256-bit   | AES Electronic Codebook mode               |
| `AES_128_CBC`     | 128-bit   | AES CBC mode (with `disablePadding: true`) |
| `AES_192_CBC`     | 192-bit   | AES CBC mode (with `disablePadding: true`) |
| `AES_256_CBC`     | 256-bit   | AES CBC mode (with `disablePadding: true`) |
| `AES_*_GCM`, etc. | All sizes | Standard algorithms (via base provider)    |

## Development

### Building

```bash
pnpm compile
```

### Testing

```bash
# Run all tests
pnpm test

# Run only unit tests
pnpm test:unit

# Run tests in watch mode
pnpm test:watch
```

### Test Coverage

The package includes comprehensive tests covering:

- MD5 hash computation
- AES ECB encryption/decryption (all key sizes)
- AES CBC no-padding encryption/decryption
- Fallback behavior to base provider
- Integration with global crypto provider
- Edge cases and error handling

## Dependencies

### Runtime Dependencies

- **[@noble/hashes](https://github.com/paulmillr/noble-hashes)** - Secure, audited hash functions
- **[@noble/ciphers](https://github.com/paulmillr/noble-ciphers)** - Secure, audited cipher implementations

### Peer Dependencies

- **pki-lite** - Base PKI-Lite library

## Security Considerations

⚠️ **Important Security Notes:**

1. **MD5 is cryptographically broken** - Only use MD5 for compatibility with legacy systems, never for new cryptographic applications
2. **ECB mode is insecure for most use cases** - ECB reveals patterns in plaintext and should only be used when specifically required by protocols
3. **CBC without padding requires careful handling** - Ensure plaintext is properly aligned to block boundaries

## Related Packages

- [pki-lite](../pki-lite/README.md) - Base PKI and cryptographic library
- [pki-lite-crypto-extended](../pki-lite-crypto-extended) - This package

## Classes

- [WebCryptoExtendedProvider](classes/WebCryptoExtendedProvider.md)

## Type Aliases

- [PbeAlgorithmMap](type-aliases/PbeAlgorithmMap.md)
