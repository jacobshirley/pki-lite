# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-09-17

### Added

- Initial release of `pki-lite-crypto-extended`
- `WebCryptoExtendedProvider` class extending base PKI-Lite crypto capabilities
- MD5 hash algorithm support using `@noble/hashes`
- AES ECB encryption support for 128/192/256-bit keys using `@noble/ciphers`
- AES CBC encryption with disabled padding support
- Automatic global crypto provider setup on import
- Comprehensive test suite with 16 unit tests
- Full TypeScript support with type definitions
- ESM module support with proper exports

### Features

- **MD5 Hashing**: Legacy hash algorithm for compatibility with older systems
- **AES ECB Mode**: Electronic Codebook encryption for specialized protocols
- **AES CBC No-Padding**: CBC mode without padding for specific use cases
- **Graceful Fallback**: Seamless integration with existing PKI-Lite crypto operations
- **Type Safety**: Full TypeScript support with proper type definitions

### Security Notes

- MD5 is cryptographically broken and should only be used for legacy compatibility
- ECB mode reveals patterns in plaintext and should be used carefully
- CBC without padding requires proper block alignment

### Dependencies

- `@noble/ciphers@1.3.0` - Secure cipher implementations
- `@noble/hashes@1.8.0` - Secure hash implementations
- `pki-lite^1.0.0` - Base PKI library (peer dependency)

### Development

- `vitest^3.2.4` - Modern testing framework
- `typescript@5.8.3` - TypeScript compiler
- `tsconfig^1.0.0` - Shared TypeScript configuration
