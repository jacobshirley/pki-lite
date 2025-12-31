**[Examples](./EXAMPLES.md)** | **[Documentation](https://jacobshirley.github.io/pki-lite/v1)**

# PKI-Lite: Lightweight Public Key Infrastructure Library

A modern, lightweight JavaScript/TypeScript library for Public Key Infrastructure (PKI) operations. PKI-Lite provides core cryptographic capabilities for working with X.509 certificates, PKCS standards, digital signatures, and more.

> **Notice:**  
> _This package is new. If you plan to use it in production, please review the code and functionality closely to ensure it meets your security and reliability requirements._

[![npm version](https://img.shields.io/npm/v/pki-lite.svg)](https://www.npmjs.com/package/pki-lite)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **X.509 Certificate Operations**: Create, validate, and manage X.509 certificates
- **PKCS Standards Support**: Implementations of PKCS#7, PKCS#5, PKCS#12
- **Digital Signatures**: Create and verify digital signatures
- **Time Stamping**: RFC 3161 time stamping protocol support
- **OCSP**: Online Certificate Status Protocol implementation
- **Certificate Revocation**: CRL (Certificate Revocation List) functionality
- **Adobe Digital Signatures**: Supports Adobe-specific signature formats

## Getting Started

### Installation

```bash
npm install pki-lite
pnpm add pki-lite
yarn add pki-lite

# If you need extended crypto functionality
npm install pki-lite-crypto-extended
pnpm add pki-lite-crypto-extended
yarn add pki-lite-crypto-extended
```

## Usage Examples

```typescript
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

const privateKeyPem = `-----BEGIN PRIVATE KEY-----{your private key here}-----END PRIVATE`
const certPem = `-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----`

const selfSigned = await Certificate.createSelfSigned({
    subject: 'CN=Test Self-Signed Certificate, O=My Organization, C=US',
    validity: {
        notBefore: new Date('2023-01-01T00:00:00Z'),
        notAfter: new Date('2024-01-01T00:00:00Z'),
    },
    privateKeyInfo: PrivateKeyInfo.fromPem(privateKeyPem),
    subjectPublicKeyInfo:
        Certificate.fromPem(certPem).tbsCertificate.subjectPublicKeyInfo,
})

console.log('Self-Signed Certificate PEM:', selfSigned.toPem())
```

For more examples, see [EXAMPLES.md](EXAMPLES.md) file or the `examples` directory.

## Crypto Providers

PKI-Lite aims to keep the number of dependencies down to improve security and reduce bundle size. This means not all cryptographic algorithms are supported out of the box. To address this, PKI-Lite uses a layered approach to cryptographic operations:

### Default: Web Crypto API

The core `pki-lite` package uses the **[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)** as its primary crypto provider. This provides:

- **Zero additional dependencies** - Uses platform-native cryptography
- **Modern algorithms** - RSA, ECDSA, SHA-256, SHA-384, SHA-512, AES-GCM
- **Cross-platform** - Works in browsers and Node.js (16+)
- **High performance** - Hardware-accelerated when available
- **Secure** - Cryptographic operations are handled by the platform

**The Web Crypto provider is sufficient for most modern PKI use cases.** [Learn more about Web Crypto API →](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

### Extended: pki-lite-crypto-extended

For legacy systems or specialized requirements, use `pki-lite-crypto-extended`:

- **Legacy algorithms** - MD5, older cipher modes
- **Password-based encryption algorithms** - 3DES, RC2, RC4, etc
- **Additional AES modes** - ECB, CBC (no padding)
- **Additional dependencies** - Pulls in libraries `node-forge`, `@noble/hashes` and `@noble/ciphers`
- **Larger bundle size** - Not recommended unless you need specific algorithms

### When to Use Extended Crypto

```typescript
// When you need legacy algorithms or specific cipher modes
// All you need is to import the extended package once,
// and any PKI operations will automatically use it.
// NB: It calls `setCryptoProvider` internally.
import 'pki-lite-crypto-extended'

// Most modern use cases - use core pki-lite
import { Certificate } from 'pki-lite/x509/Certificate.js'
```

**Recommendation**: Start with the core `pki-lite` package. Only add `pki-lite-crypto-extended` if you encounter specific algorithm requirements that Web Crypto doesn't support.

## Packages

This monorepo contains the following packages:

| Package                    | Description                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------ |
| `pki-lite`                 | Core PKI functionality with essential cryptographic operations                       |
| `pki-lite-crypto-extended` | Extended cryptographic capabilities including MD5 hashing and AES ECB/CBC encryption |

## Project aims

- **Lightweight**: Minimal dependencies to reduce bundle size and improve security
- **Cross-Platform**: Works seamlessly in both browser and Node.js environments
- **Modern Standards**: Supports the latest PKI standards
- **Extensible**: Easy to add new algorithms and structures
- **Secure**: Prioritizes security best practices in all implementations

## Development

### Compilation

```bash
# Compile all packages
pnpm compile

# Watch mode for development
cd packages/pki-lite
pnpm watch
```

### Testing

```bash
# Run all tests
pnpm test

# Run unit tests for a specific package
cd packages/pki-lite
pnpm test:unit

# Run acceptance tests
pnpm test:acceptance

# Run integration tests
pnpm test:integration
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Acknowledgments

- Uses [asn1js](https://www.npmjs.com/package/asn1js) for ASN.1 parsing and serialization
- Extended crypto functionality provided by [noble-hashes](https://github.com/paulmillr/noble-hashes) and [noble-ciphers](https://github.com/paulmillr/noble-ciphers) and [node-forge](https://github.com/digitalbazaar/forge)
