# Contributing to PKI-Lite

Thank you for your interest in contributing to PKI-Lite! This guide will help you understand the project structure and maintain consistency with the existing codebase.

## Project Aims

PKI-Lite is designed to be:

- **Lightweight**: Minimal dependencies to reduce bundle size and improve security
- **Cross-Platform**: Works seamlessly in both browser and Node.js environments
- **Modern Standards**: Supports the latest PKI standards
- **Extensible**: Easy to add new algorithms and structures
- **Secure**: Prioritizes security best practices in all implementations

## Project Structure

```
packages/
├── pki-lite/                    # Core PKI functionality
│   ├── src/
│   │   ├── adobe/              # Adobe-specific signature formats
│   │   ├── algorithms/         # Cryptographic algorithm implementations
│   │   ├── asn1/              # ASN.1 type implementations
│   │   ├── core/              # Core utilities and base classes
│   │   ├── keys/              # Key management (public/private keys)
│   │   ├── ocsp/              # Online Certificate Status Protocol
│   │   ├── pkcs5/             # PKCS#5 standard implementation
│   │   ├── pkcs7/             # PKCS#7 standard implementation
│   │   ├── pkcs12/            # PKCS#12 standard implementation
│   │   ├── revocation/        # Certificate revocation (CRL)
│   │   ├── timestamp/         # RFC 3161 time stamping
│   │   └── x509/              # X.509 certificate operations
│   └── test/                  # Integration and acceptance tests
└── pki-lite-crypto-extended/   # Extended crypto algorithms
```

## Code Standards

### 1. ASN.1 Documentation

All classes representing ASN.1 structures **must** include the ASN.1 definition in their JSDoc:

````typescript
/**
 * Represents an X.509 certificate.
 *
 * @asn
 * ```asn
 * Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING
 * }
 * ```
 */
export class Certificate extends PkiBase<Certificate> {
    // Implementation...
}
````

### 2. Test Files

Every source file **must** have a corresponding test file in the same directory:

```
src/x509/Certificate.ts
src/x509/Certificate.test.ts
```

Tests should cover:

- Basic construction and parsing
- Edge cases and error conditions
- Round-trip serialization (parse → serialize → parse)
- Real-world examples when possible

### 3. Examples

All new features and public APIs **must** include practical examples in the `examples/` folder:

```
examples/
├── certificates/
│   ├── create-self-signed.ts
│   ├── validate-certificate.ts
│   └── certificate-chain.ts
├── signatures/
│   ├── digital-signature.ts
│   └── timestamp-signature.ts
└── README.md
```

Examples should:

- Be fully functional and runnable
- Include clear comments explaining each step
- Cover real-world use cases
- Be referenced in the main documentation

### 4. Consistent Class Structure

Follow this structure for all PKI classes:

```typescript
export class YourClass extends PkiBase<YourClass> {
    // 1. Public properties (ASN.1 fields)
    public field1: Type1
    public field2: Type2

    // 2. Constructor
    constructor(options: { field1: Type1; field2: Type2 }) {
        super()
        this.field1 = options.field1
        this.field2 = options.field2
    }

    // 3. Static factory methods
    static fromAsn1(asn1: Asn1Any): YourClass {
        /* ... */
    }
    static fromDer(der: Uint8Array): YourClass {
        /* ... */
    }
    static fromPem(pem: string): YourClass {
        /* ... */
    }

    // 4. Instance methods
    toAsn1(): Asn1Any {
        /* ... */
    }
    toDer(): Uint8Array {
        /* ... */
    }
    toPem(): string {
        /* ... */
    }
    toString(): string {
        /* ... */
    }
}
```

## Adding New Crypto Algorithms

### 1. Algorithm Identifier Support

First, add the algorithm OID to `src/core/OIDs.ts`:

```typescript
export const OIDs = {
    // ... existing OIDs
    newAlgorithm: '1.2.3.4.5.6.7',
} as const
```

### 2. Create Algorithm Parameters Class

If the algorithm requires parameters, create a new class in `src/algorithms/`:

````typescript
/**
 * Parameters for NewAlgorithm.
 *
 * @asn
 * ```asn
 * NewAlgorithmParams ::= SEQUENCE {
 *     parameter1    INTEGER,
 *     parameter2    OCTET STRING OPTIONAL
 * }
 * ```
 */
export class NewAlgorithmParams extends PkiBase<NewAlgorithmParams> {
    parameter1: number
    parameter2?: Uint8Array

    // ... follow standard class structure
}
````

### 3. Update AlgorithmIdentifier

Add support in `src/algorithms/AlgorithmIdentifier.ts`:

```typescript
// In the parseParameters method:
case OIDs.newAlgorithm:
    return NewAlgorithmParams.fromAsn1(parametersAsn1)

// In the createParameters method:
case OIDs.newAlgorithm:
    return (parameters as NewAlgorithmParams).toAsn1()
```

### 4. Implement Crypto Operations

Add crypto provider support in the appropriate crypto provider files:

```typescript
// For core algorithms, update WebCryptoProvider
// For extended algorithms, update WebCryptoExtendedProvider

async newAlgorithmOperation(
    data: Uint8Array,
    key: CryptoKey,
    params: NewAlgorithmParams
): Promise<Uint8Array> {
    // Implementation using Web Crypto API or fallback library
}
```

### 5. Add Tests

Create comprehensive tests covering:

```typescript
describe('NewAlgorithm', () => {
    test('should parse parameters correctly', () => {
        // Test parameter parsing
    })

    test('should perform crypto operations', async () => {
        // Test actual cryptographic operations
    })

    test('should handle edge cases', () => {
        // Test error conditions
    })
})
```

## Development Workflow

### Setup

```bash
# Install dependencies
pnpm install

# Compile all packages
pnpm compile
```

### Testing

```bash
# Run all tests
pnpm test

# Run tests for specific package
cd packages/pki-lite
pnpm test:unit

# Run tests in specific environment
pnpm test --project=node     # Node.js environment
pnpm test --project=browser  # Browser environment

# Watch mode during development
pnpm test:watch
```

### Code Quality

```bash
# Format code with Prettier
pnpm format

# Lint code
pnpm lint

# Type check
pnpm type-check
```

**Note**: This project uses [Prettier](https://prettier.io/) for code formatting. All code is automatically formatted on commit via pre-commit hooks.

## Submission Guidelines

1. **Fork** the repository and create a feature branch
2. **Follow** the coding standards outlined above
3. **Add tests** for all new functionality
4. **Include examples** in documentation
5. **Update** relevant documentation
6. **Ensure** all tests pass and code is properly formatted
7. **Use conventional commit messages** (e.g., `feat: add new algorithm`, `fix: resolve parsing issue`, `docs: update contributing guide`)
8. **Submit** a pull request with a clear description

### Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Examples:

- `feat(x509): add certificate validation method`
- `fix(algorithms): resolve RSA-PSS parameter parsing`
- `docs: add usage examples for PKCS#7`
- `test(ocsp): add integration tests for OCSP client`

## Questions?

If you have questions about contributing, please:

1. Check existing issues and discussions
2. Review the codebase for similar implementations
3. Open an issue for clarification

Thank you for helping make PKI-Lite better!
