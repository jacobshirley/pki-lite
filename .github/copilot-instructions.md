# PKI-Lite: Public Key Infrastructure Library

PKI-Lite is a modern TypeScript/JavaScript library for Public Key Infrastructure (PKI) operations, providing X.509 certificate handling, PKCS standards, digital signatures, and cryptographic operations. It's organized as a monorepo with two main packages: core PKI functionality and extended cryptographic capabilities.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites and Setup
- Node.js v20.19.5 (>=16.x supported)
- pnpm 10.14.0 (REQUIRED - do not use npm/yarn)

### Initial Setup (First Time)
Bootstrap, build, and test the repository:
```bash
# Install pnpm globally if not available
npm install -g pnpm@10.14.0

# Install dependencies (takes ~6 seconds)
pnpm install

# Compile all packages (takes ~18 seconds) - NEVER CANCEL
pnpm compile

# Run Node.js tests (takes ~7 seconds for node tests)
cd packages/pki-lite && pnpm test:node
```

### Build and Compilation
```bash
# Compile all packages - NEVER CANCEL, takes ~18 seconds. Set timeout to 60+ seconds.
pnpm compile

# Watch mode for development (run in individual packages)
cd packages/pki-lite
pnpm watch

# Validate TypeScript without compilation
pnpm compile:validate
```

### Testing
**CRITICAL BROWSER TEST LIMITATION**: Browser tests require Playwright Chromium installation which frequently fails due to download issues. Use Node.js-only tests for reliable validation.

```bash
# Working Tests (RELIABLE):
# Run Node.js-only tests - NEVER CANCEL, takes ~7 seconds. Set timeout to 30+ seconds.
cd packages/pki-lite && pnpm test:node

# Run crypto-extended tests with browser disabled - takes ~2 seconds
cd packages/pki-lite-crypto-extended && pnpm test:acceptance

# PROBLEMATIC Tests (Playwright Issues):
# These commands FAIL due to Playwright Chromium download issues:
# pnpm test (fails - requires browser)
# pnpm test:unit (fails - requires browser)
# pnpm test:acceptance (fails - requires browser for pki-lite package)

# If browser tests are needed, try:
# 1. npm install -g playwright && playwright install chromium
# 2. If download fails (common), document as known limitation
```

### Running Examples
Examples demonstrate core functionality and can be used for validation:
```bash
# ALWAYS compile first
pnpm compile

# Run self-signed certificate example (takes ~7 seconds)
cd packages/pki-lite
npx tsx examples/self-signed-certificate.ts

# Other examples:
npx tsx examples/pfx-bags.ts
npx tsx examples/crl-request.ts
npx tsx examples/ocsp-request.ts
npx tsx examples/timestamp-request.ts

# Run crypto-extended tests (examples are not directly runnable)
cd packages/pki-lite-crypto-extended
pnpm test:acceptance
```

## Validation
**MANUAL VALIDATION REQUIREMENT**: After making changes, always validate functionality using examples:

### Standard Validation Workflow
```bash
# 1. Compile (NEVER CANCEL - 18 seconds)
pnpm compile

# 2. Run Node.js tests (7 seconds)
cd packages/pki-lite && pnpm test:node

# 3. Test core functionality with examples
npx tsx examples/self-signed-certificate.ts

# 4. Test crypto-extended if modified
cd packages/pki-lite-crypto-extended && pnpm test:acceptance
```

### Functional Validation Scenarios
After making changes, ALWAYS test these scenarios:
1. **Certificate Generation**: Run `npx tsx examples/self-signed-certificate.ts` and verify PEM certificate output
2. **PKCS#12 Operations**: Run `npx tsx examples/pfx-bags.ts` and verify successful parsing
3. **Core PKI Tests**: Run `pnpm test:node` and ensure all 6 tests pass
4. **Crypto-Extended**: Run `cd packages/pki-lite-crypto-extended && pnpm test:acceptance` and verify 2 tests pass

## Common Tasks

### Project Structure
```
pki-lite/                          # Monorepo root
├── packages/
│   ├── pki-lite/                  # Core PKI library
│   │   ├── src/                   # Source code
│   │   │   ├── x509/             # X.509 certificate handling
│   │   │   ├── pkcs12/           # PKCS#12 (PFX) support
│   │   │   ├── pkcs7/            # PKCS#7 signature support
│   │   │   ├── core/             # Core cryptographic operations
│   │   │   ├── ocsp/             # OCSP protocol support
│   │   │   ├── timestamp/        # RFC 3161 timestamping
│   │   │   └── revocation/       # CRL and revocation
│   │   ├── examples/             # Working code examples
│   │   └── test/                 # Test suites
│   └── pki-lite-crypto-extended/ # Extended crypto provider
│       ├── src/                  # MD5, AES ECB/CBC implementations
│       ├── examples/             # Usage examples
│       └── test/                 # Test suites
├── .github/workflows/test.yaml   # CI pipeline
└── pnpm-workspace.yaml          # Workspace configuration
```

### Key Files and Locations
- **Core PKI Classes**: `packages/pki-lite/src/x509/`, `packages/pki-lite/src/core/`
- **Examples**: `packages/pki-lite/examples/` - Always test changes here
- **Extended Crypto**: `packages/pki-lite-crypto-extended/src/`
- **CI Configuration**: `.github/workflows/test.yaml`
- **Package Configs**: `packages/*/package.json`

### Development Workflow
1. Make changes to source files
2. Run `pnpm compile` (18 seconds)
3. Test with Node.js tests: `cd packages/pki-lite && pnpm test:node`
4. Validate with examples: `npx tsx examples/self-signed-certificate.ts`
5. For crypto changes: `cd packages/pki-lite-crypto-extended && pnpm test:acceptance`

### Commit Practices
- Always compile and test before committing
- Run the complete validation workflow: `pnpm compile && cd packages/pki-lite && pnpm test:node && npx tsx examples/self-signed-certificate.ts && npx tsx examples/pfx-bags.ts && cd ../pki-lite-crypto-extended && pnpm test:acceptance`
- Commit message should be descriptive of the PKI functionality changed
- Test any examples related to your changes

### CI Pipeline Expectations
The GitHub Actions workflow (`.github/workflows/test.yaml`) runs:
1. pnpm install
2. Playwright browser installation
3. pnpm compile
4. pnpm test (full test suite including browser tests)

**CI Note**: Browser tests work in CI environment but fail locally due to Playwright download issues.

## Known Issues and Workarounds

### Playwright Browser Test Failures
**Issue**: Local Playwright Chromium installation fails with download size mismatch errors.
**Workaround**: Use Node.js-only tests (`pnpm test:node`) for development validation.
**Status**: Browser tests pass in CI environment.

### Package Dependencies
- **Runtime**: ASN.1 JS, Noble Hashes, Noble Ciphers
- **Dev**: TypeScript 5.8.2, Vitest 4.0.0-beta.11, Playwright 1.55.0
- **Monorepo**: pnpm workspaces

## Quick Reference Commands
```bash
# Fresh setup
npm install -g pnpm@10.14.0 && pnpm install && pnpm compile

# Development cycle
pnpm compile && cd packages/pki-lite && pnpm test:node && npx tsx examples/self-signed-certificate.ts

# Extended crypto validation
cd packages/pki-lite-crypto-extended && pnpm test:acceptance

# Watch mode development
cd packages/pki-lite && pnpm watch
```

## Architecture Notes
- **Monorepo**: Two packages with shared dependencies
- **TypeScript**: ES modules with strict type checking
- **Testing**: Vitest with Node.js and browser environments
- **Examples**: Comprehensive demonstrations in TypeScript
- **Crypto**: WebCrypto API with Noble libraries for extended algorithms