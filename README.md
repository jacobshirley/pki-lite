# PKI-Lite: Lightweight Public Key Infrastructure Library

A modern, lightweight JavaScript/TypeScript library for Public Key Infrastructure (PKI) operations. PKI-Lite provides core cryptographic capabilities for working with X.509 certificates, PKCS standards, digital signatures, and more.

## Features

- **X.509 Certificate Operations**: Create, validate, and manage X.509 certificates
- **PKCS Standards Support**: Implementations of PKCS#7, PKCS#5, PKCS#12
- **Digital Signatures**: Create and verify digital signatures
- **Time Stamping**: RFC 3161 time stamping protocol support
- **OCSP**: Online Certificate Status Protocol implementation
- **Certificate Revocation**: CRL (Certificate Revocation List) functionality
- **Adobe Digital Signature Support**: Work with PDF signatures

## Packages

This monorepo contains the following packages:

| Package | Description |
|---------|-------------|
| `pki-lite` | Core PKI functionality with essential cryptographic operations |
| `pki-lite-crypto-extended` | Extended cryptographic capabilities including MD5 hashing and AES ECB/CBC encryption |

## Getting Started

### Prerequisites

- Node.js (>=16.x)
- pnpm 10.14.0

### Installation

```bash
# Install from npm
npm install pki-lite

# If you need extended crypto functionality
npm install pki-lite-crypto-extended
```

For developers working on the library:

```bash
# Clone the repository
git clone https://github.com/jacobshirley/pki-lite.git
cd pki-lite

# Install dependencies
pnpm install

# Compile all packages
pnpm compile

# Run tests
pnpm test
```

## Usage Examples

```typescript
import { X509Certificate } from 'pki-lite/x509/X509Certificate';
import { RSAKeyPair } from 'pki-lite/keys/RSAKeyPair';

// Generate a key pair
const keyPair = await RSAKeyPair.generate(2048);

// Create a self-signed certificate
const cert = await X509Certificate.createSelfSigned({
  subject: { commonName: 'example.com' },
  keyPair,
  validityPeriod: { years: 1 }
});

// Export to PEM format
const pemCertificate = cert.toPEM();
```

For more examples, check the documentation and examples directory.

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

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the LICENSE file for details.

## Acknowledgments

- Built with TypeScript
- Uses ASN.1 JS for ASN.1 encoding/decoding
- Extended crypto functionality provided by Noble Hashes and Noble Ciphers