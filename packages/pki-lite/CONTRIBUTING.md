# Contributing to pki-lite

Thank you for your interest in contributing to pki-lite! This document provides an overview of the main concepts, architecture, and contribution guidelines for the package.

## Overview

pki-lite is a lightweight Public Key Infrastructure (PKI) library for JavaScript/TypeScript that provides comprehensive support for X.509 certificates, PKCS standards, and cryptographic operations. It's designed to work in both browser and Node.js environments with minimal dependencies.

## Main Concepts

### Architecture

The package is organized around several core concepts:

1. **PkiBase** - The foundational class that all PKI objects inherit from, providing common functionality like ASN.1 conversions, DER encoding/decoding, and PEM formatting.

2. **ASN.1/DER Encoding** - ASN.1 (Abstract Syntax Notation One) is used extensively throughout PKI for encoding data structures. The library uses the `asn1js` library for low-level ASN.1 operations.

3. **X.509 Certificates** - The standard defining the format of public key certificates used in TLS/SSL.

4. **PKCS Standards** - A set of standards for public-key cryptography developed by RSA Security:
    - PKCS#5: Password-based encryption
    - PKCS#7: Cryptographic message syntax (used for digital signatures and encryption)
    - PKCS#12: Personal Information Exchange (PFX) format for storing private keys with their certificates

5. **Crypto Provider** - An abstraction layer over cryptographic operations, allowing the library to work with different crypto implementations.

### Directory Structure

```
src/
├── adobe/          # Adobe-specific signature formats
├── algorithms/     # Cryptographic algorithm identifiers
├── asn1/           # ASN.1 types and utilities
├── core/           # Core functionality and base classes
│   ├── crypto/     # Cryptographic operations
│   ├── errors/     # Error types
│   ├── OIDs.js     # Object Identifiers used in PKI
│   ├── PkiBase.js  # Base class for all PKI objects
│   └── ...
├── keys/           # Key management (public/private keys)
├── ocsp/           # Online Certificate Status Protocol
├── pkcs5/          # Password-based encryption
├── pkcs7/          # Cryptographic message syntax
├── pkcs12/         # Personal Information Exchange format
├── revocation/     # Certificate revocation mechanisms
├── timestamp/      # Timestamp protocol
└── x509/           # X.509 certificate structures
    ├── extensions/ # X.509 certificate extensions
    └── ...
```

## Core Classes

### PkiBase

The `PkiBase` class is the foundation of the library. It provides:

- Conversion between different formats (ASN.1, DER, PEM, JSON)
- Common functionality for all PKI objects
- Type safety through TypeScript generics

Example:

```typescript
export abstract class PkiBase<T extends object = any> {
    abstract toAsn1(): Asn1BaseBlock
    toDer(): Uint8Array {
        /* ... */
    }
    toPem(): string {
        /* ... */
    }
    toJSON(): ToJson<T> {
        /* ... */
    }
    // ...
}
```

### Certificate

The `Certificate` class represents an X.509 certificate and extends `PkiBase`. It provides:

- Parsing certificates from PEM/DER formats
- Creating self-signed certificates
- Verifying certificate signatures
- Accessing certificate fields and extensions
- Working with certificate chains

### CertificateValidator

The `CertificateValidator` handles certificate validation including:

- Chain building and validation
- Validity period checking
- Revocation checking via CRL and OCSP
- Trust anchor verification
- Name constraints checking

### PFX

The `PFX` class handles PKCS#12 files (commonly used for certificates with private keys):

- Parsing PFX/P12 files
- Extracting certificates and private keys
- Verifying integrity of the PFX data

## Contribution Guidelines

### Adding New Features

1. **Understand the existing architecture**:
    - New components should follow the established patterns
    - Extend the appropriate base classes
    - Maintain immutability where possible

2. **ASN.1 Structures**:
    - Include ASN.1 syntax in comments for reference
    - Follow the exact ASN.1 specification for the structure
    - Example:
        ````typescript
        /**
         * @asn
         * ```asn
         * Certificate  ::=  SEQUENCE  {
         *   tbsCertificate       TBSCertificate,
         *   signatureAlgorithm   AlgorithmIdentifier,
         *   signatureValue       BIT STRING
         * }
         * ```
         */
        ````

3. **Error Handling**:
    - Use specific error types from the `core/errors` directory
    - Provide detailed error messages

### Testing

1. **Unit Tests**:
    - All components should have unit tests
    - Test both success and failure cases
    - Use fixture data for tests

2. **Integration Tests**:
    - Test interoperability with other systems
    - Verify compliance with standards

3. **Acceptance Tests**:
    - Test real-world scenarios
    - Verify against external certificate authorities

### Code Style

1. **TypeScript Best Practices**:
    - Use strict typing
    - Document public APIs with JSDoc
    - Follow functional programming principles where appropriate

2. **Naming Conventions**:
    - Use PascalCase for classes
    - Use camelCase for methods and properties
    - Follow ASN.1/X.509 naming when applicable

## Cryptographic Considerations

1. **Security**:
    - Avoid implementing cryptographic algorithms directly
    - Use platform cryptography (WebCrypto API, Node.js crypto)
    - Be aware of timing attacks and other side-channel vulnerabilities

2. **Standards Compliance**:
    - Follow relevant RFCs (5280, 2986, etc.)
    - Ensure interoperability with other PKI systems

## Common Tasks

### Adding a New X.509 Extension

1. Create a new class in the `x509/extensions` directory
2. Extend the appropriate base class (usually `Extension`)
3. Implement the ASN.1 structure according to the RFC
4. Add appropriate getters and utility methods
5. Add unit tests

### Adding Support for a New Crypto Algorithm

1. Update the `algorithms/AlgorithmIdentifier.js` file
2. Add the OID to `core/OIDs.js`
3. Implement the algorithm in the crypto provider if needed
4. Add tests verifying the algorithm works correctly

## Getting Help

If you're unsure about anything, you can:

1. Review the existing code for similar patterns
2. Check the relevant RFC or standard
3. Look at the test files for usage examples

Thank you for contributing to pki-lite!
