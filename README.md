# @devex/pki-lite

A lightweight, modern JavaScript/TypeScript library for Public Key Infrastructure (PKI) operations in browser and Node.js environments. This package provides comprehensive support for X.509 certificates, PKCS standards, and cryptographic operations with minimal dependencies.

## Features

- **X.509 Certificate Operations**: Create, parse, validate, and manipulate X.509 certificates
- **PKCS Support**: Implementation of PKCS standards including PKCS#7, PKCS#5, and PKCS#12
- **Digital Signatures**: Create and verify signatures using various algorithms
- **Certificate Validation**: Validate certificate chains, revocation status via CRL and OCSP
- **ASN.1/DER Encoding/Decoding**: Parse and generate ASN.1 DER-encoded structures
- **PEM Format Support**: Convert between PEM and binary formats
- **Timestamp Support**: Create and validate timestamp tokens
- **OCSP Support**: Generate OCSP requests and parse responses
- **Adobe Signature Support**: Work with PDF digital signatures

## Installation

```bash
npm install @devex/pki-lite
# or
pnpm add @devex/pki-lite
# or
yarn add @devex/pki-lite
```

## Basic Usage

### Working with X.509 Certificates

```typescript
import { Certificate } from '@devex/pki-lite/x509/Certificate'

// Parse a certificate from PEM format
const cert = Certificate.fromPem(`-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIJANVUhU6Gj9WAMA0GCSqGSIb3DQEBCwUAMD0xCzAJBgNV
...
-----END CERTIFICATE-----`)

// Access certificate information
console.log('Subject:', cert.tbsCertificate.subject.toString())
console.log('Issuer:', cert.tbsCertificate.issuer.toString())
console.log('Valid from:', cert.tbsCertificate.validity.notBefore)
console.log('Valid until:', cert.tbsCertificate.validity.notAfter)

// Verify certificate signature
const isSignatureValid = await cert.verifySignature()
console.log('Signature valid:', isSignatureValid)

// Convert to PEM format
const pemString = cert.toPem()
```

### Creating a Self-Signed Certificate

```typescript
import { Certificate } from '@devex/pki-lite/x509/Certificate'
import { PrivateKeyInfo } from '@devex/pki-lite/keys/PrivateKeyInfo'

// Create a self-signed certificate
const selfSigned = await Certificate.createSelfSignedCertificate({
    subject: 'CN=Test Self-Signed Certificate, O=My Organization, C=US',
    validity: {
        notBefore: new Date('2023-01-01T00:00:00Z'),
        notAfter: new Date('2024-01-01T00:00:00Z'),
    },
    privateKeyInfo: PrivateKeyInfo.fromPem(privateKeyPem),
    subjectPublicKeyInfo: publicKeyInfo,
})

console.log('Self-Signed Certificate PEM:', selfSigned.toPem())
```

### Working with PKCS#12 (PFX) Files

```typescript
import { PFX } from '@devex/pki-lite/pkcs12/PFX'

// Parse a PFX/P12 file
const pfx = PFX.fromPem(pfxPemString)

// Extract private keys (providing the password)
const privateKeys = await pfx.getPrivateKeys('password')
privateKeys.forEach((key, index) => {
    console.log(`Private Key ${index + 1}:`, key.getPrivateKey().toPem())
})

// Extract certificates
const certificates = await pfx.getX509Certificates('password')
certificates.forEach((cert, index) => {
    console.log(`Certificate ${index + 1}:`, cert.toPem())
})
```

### Certificate Validation

```typescript
import { Certificate } from '@devex/pki-lite/x509/Certificate'
import { CertificateValidator } from '@devex/pki-lite/core/CertificateValidator'

// Create validator with trust anchors (root certificates)
const validator = new CertificateValidator({
    trustAnchors: [rootCertificate1, rootCertificate2],
})

// Validate a certificate
const result = await validator.validate(certificate, {
    checkRevocation: true,
    date: new Date(),
})

console.log('Validation status:', result.status)
if (result.revocationStatus) {
    console.log('Revocation info:', result.revocationStatus)
}
```

### Working with Certificate Revocation Lists (CRLs)

```typescript
import { CertificateList } from '@devex/pki-lite/x509/CertificateList'

// Parse a CRL from PEM format
const crl = CertificateList.fromPem(`-----BEGIN X509 CRL-----
MIIBYDCBygIBATANBgkqhkiG9w0BAQUFADBDMQswCQYDVQQGEwJVUzEiMCAGA1UE
...
-----END X509 CRL-----`)

// Check if a certificate is revoked
const isRevoked = crl.isRevoked(certificateSerialNumber)
console.log('Certificate revoked:', isRevoked)

// Get revoked certificate information
const revokedCerts = crl.tbsCertList.revokedCertificates
revokedCerts.forEach((cert) => {
    console.log('Serial:', cert.userCertificate)
    console.log('Revocation date:', cert.revocationDate)
})
```

### OCSP Requests and Responses

```typescript
import { Certificate } from '@devex/pki-lite/x509/Certificate'
import { OCSPRequest } from '@devex/pki-lite/ocsp/OCSPRequest'
import { OCSPResponse } from '@devex/pki-lite/ocsp/OCSPResponse'

// Create an OCSP request
const request = await OCSPRequest.create({
    certificate: subjectCertificate,
    issuerCertificate: issuerCertificate,
})

// Convert to DER for sending to OCSP responder
const requestDer = request.toDer()

// Parse OCSP response
const response = OCSPResponse.fromDer(ocspResponseDer)
console.log('OCSP status:', response.responseStatus)

// Check certificate status
const certStatus = response.getCertificateStatus(
    subjectCertificate,
    issuerCertificate,
)
console.log('Certificate status:', certStatus.status)
```

## API Reference

### Core Classes

#### `PkiBase`

Base class for all PKI objects with common functionality:

- `toAsn1()`: Convert to ASN.1 structure
- `toDer()`: Convert to DER-encoded binary format
- `toPem()`: Convert to PEM format
- `toJSON()`: Convert to JSON format
- `toString()`: Get string representation
- `toHumanString()`: Get human-readable string representation

#### `Certificate`

Represents an X.509 certificate:

- `static fromPem(pemString)`: Create from PEM string
- `static fromDer(derBytes)`: Create from DER-encoded binary
- `static createSelfSignedCertificate(options)`: Create a self-signed certificate
- `verifySignature()`: Verify certificate signature
- `getExtension(oid)`: Get a specific extension
- `hasExtension(oid)`: Check if extension exists
- `getIssuerOCSPURLs()`: Get OCSP URLs from AIA extension
- `getCRLDistributionPoints()`: Get CRL distribution points

#### `CertificateValidator`

Validates certificates and certificate chains:

- `constructor(options)`: Create with trust anchors and validation options
- `validate(certificate, options)`: Validate a certificate
- `buildAndValidateCertPath(certificate)`: Build and validate certificate path
- `checkRevocation(certificate, issuer)`: Check certificate revocation status

#### `PrivateKeyInfo` and `SubjectPublicKeyInfo`

Handle private and public keys:

- `static fromPem(pemString)`: Create from PEM string
- `static fromDer(derBytes)`: Create from DER-encoded binary
- `getPublicKey()`: Get public key (for PrivateKeyInfo)
- `getPrivateKey()`: Get private key
- `toPem()`: Convert to PEM format

#### `PFX`

PKCS#12 container for certificates and private keys:

- `static fromPem(pemString)`: Create from PEM string
- `static fromDer(derBytes)`: Create from DER-encoded binary
- `getBags(password)`: Get all safe bags
- `getPrivateKeys(password)`: Get private keys
- `getX509Certificates(password)`: Get X.509 certificates
- `verifySafeBags(password)`: Verify integrity

### Other Components

- **PKCS#7**: Digital signature and encryption envelope formats
- **PKCS#5**: Password-based encryption
- **X.509 Extensions**: Support for standard extensions
- **ASN.1 Types**: Various ASN.1 type implementations
- **Cryptographic Algorithms**: Support for various algorithms

## Examples

See the [examples directory](./examples) for more detailed usage examples:

- [Self-signed certificate creation](./examples/self-signed-certificate.ts)
- [PKCS#12 (PFX) parsing](./examples/pfx-bags.ts)
- [CRL request handling](./examples/crl-request.ts)
- [OCSP request handling](./examples/ocsp-request.ts)
- [Timestamp request handling](./examples/timestamp-request.ts)

## Running Tests

```bash
# Run all tests
pnpm test

# Run unit tests only
pnpm test:unit

# Run acceptance tests
pnpm test:acceptance

# Run integration tests
pnpm test:integration

# Run examples as tests
pnpm test:examples
```

When updating the API or documentation, ensure the examples are also updated and type-check correctly.

## Building

```bash
# Compile the package
pnpm compile

# Watch mode for development
pnpm watch
```

## License

ISC

## Dependencies

- [asn1js](https://github.com/PeculiarVentures/asn1js): ASN.1 parser and serializer

## See Also

- [@devex/pki-lite-crypto-extended](../pki-lite-crypto-extended): Extended cryptographic operations for pki-lite
