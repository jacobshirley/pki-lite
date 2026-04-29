// Using the Certificate Builder for flexible certificate creation

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { GeneralName } from 'pki-lite/x509/GeneralName.js'

console.log('=== Certificate Builder Examples ===\n')

// Generate keys for the examples
console.log('Generating key pairs...')
const keyPair1 = await KeyGen.generateRsaPair({ keySize: 2048 })
const keyPair2 = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
console.log('✓ Key pairs generated\n')

// Example 1: Basic self-signed certificate with minimal configuration
console.log('=== Example 1: Basic Self-Signed Certificate ===')
const basicCert = await Certificate.builder()
    .setSubject('CN=Basic Certificate')
    .setPublicKey(keyPair1.publicKey)
    .setPrivateKey(keyPair1.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .selfSign()

console.log('✓ Basic certificate created')
console.log('  Subject:', basicCert.tbsCertificate.subject.toString())
console.log('  Serial:', basicCert.tbsCertificate.serialNumber.toString())

// Example 2: Certificate with specific validity period
console.log('\n=== Example 2: Certificate with Specific Validity Period ===')
const startDate = new Date('2024-01-01T00:00:00Z')
const endDate = new Date('2025-01-01T00:00:00Z')

const timedCert = await Certificate.builder()
    .setSubject('CN=Timed Certificate, O=Example Org')
    .setPublicKey(keyPair1.publicKey)
    .setPrivateKey(keyPair1.privateKey)
    .setValidityPeriod(startDate, endDate)
    .generateSerialNumber()
    .selfSign()

console.log('✓ Timed certificate created')
console.log(
    '  Valid from:',
    timedCert.tbsCertificate.validity.notBefore.toISOString(),
)
console.log(
    '  Valid until:',
    timedCert.tbsCertificate.validity.notAfter.toISOString(),
)

// Example 3: Server certificate with extensions using builder helpers
console.log('\n=== Example 3: Server Certificate with Extensions ===')
const serverCert = await Certificate.builder()
    .setSubject('CN=api.example.com, O=Example Organization, C=US')
    .setPublicKey(keyPair1.publicKey)
    .setPrivateKey(keyPair1.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .addExtendedKeyUsage({
        serverAuth: true,
        clientAuth: true,
    })
    .addSubjectAltName(
        'api.example.com',
        '*.api.example.com',
        new GeneralName.rfc822Name({ value: 'admin@example.com' }),
    )
    .addBasicConstraints(false) // Not a CA
    .selfSign()

console.log('✓ Server certificate created')
console.log('  Extensions:', serverCert.tbsCertificate.extensions?.length ?? 0)

// Example 4: EC certificate with specific algorithm
console.log('\n=== Example 4: EC Certificate with Custom Algorithm ===')
const ecCert = await Certificate.builder()
    .setSubject('CN=EC Certificate')
    .setPublicKey(keyPair2.publicKey)
    .setPrivateKey(keyPair2.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .setAlgorithm({
        type: 'ECDSA',
        params: { namedCurve: 'P-256', hash: 'SHA-256' },
    })
    .selfSign()

console.log('✓ EC certificate created')
console.log('  Algorithm:', ecCert.signatureAlgorithm.algorithm.toString())

// Example 5: CA certificate with path length constraint
console.log('\n=== Example 5: CA Certificate with Path Length Constraint ===')
const caKeyPair = await KeyGen.generateRsaPair({ keySize: 4096 })

const caCert = await Certificate.builder()
    .setSubject('CN=Example Root CA, O=Example Org, C=US')
    .setPublicKey(caKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(3650) // 10 years
    .generateSerialNumber()
    .addBasicConstraints(true, 1) // CA with path length 1
    .addKeyUsage({
        keyCertSign: true,
        cRLSign: true,
    })
    .setVersion(2) // X.509 v3
    .selfSign()

console.log('✓ CA certificate created')
console.log('  Subject:', caCert.tbsCertificate.subject.toString())
console.log('  Is CA: true')
console.log('  Path Length Constraint: 1')

// Example 6: Issuing a certificate from the CA
console.log('\n=== Example 6: Certificate Issued by CA ===')
const userKeyPair = await KeyGen.generateRsaPair()

const issuedCert = await Certificate.builder()
    .setSubject('CN=John Doe, O=Example Org, C=US')
    .setIssuer(caCert) // Set the CA as issuer
    .setPublicKey(userKeyPair.publicKey)
    .setIssuerPrivateKey(caKeyPair.privateKey) // Use CA's private key to sign
    .setValidityDays(365)
    .generateSerialNumber()
    .addBasicConstraints(false) // Not a CA
    .sign()

console.log('✓ User certificate issued by CA')
console.log('  Subject:', issuedCert.tbsCertificate.subject.toString())
console.log('  Issuer:', issuedCert.tbsCertificate.issuer.toString())

// Verify the issued certificate
const isValid = await issuedCert.isIssuedBy(caCert)
console.log('  Signature valid:', isValid)

// Example 7: Custom serial number
console.log('\n=== Example 7: Certificate with Custom Serial Number ===')
const customSerial = new Uint8Array([
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
])

const customSerialCert = await Certificate.builder()
    .setSubject('CN=Custom Serial')
    .setPublicKey(keyPair1.publicKey)
    .setPrivateKey(keyPair1.privateKey)
    .setValidityDays(365)
    .setSerialNumber(customSerial)
    .selfSign()

console.log('✓ Certificate with custom serial created')
console.log(
    '  Serial:',
    customSerialCert.tbsCertificate.serialNumber.toString(),
)

console.log('\n=== All Examples Completed ===')
console.log('\nCertificate Builder Features:')
console.log('  • Fluent API for creating certificates')
console.log('  • Helper methods for common extensions:')
console.log('    - addKeyUsage() - Key usage flags')
console.log('    - addExtendedKeyUsage() - Extended key usage purposes')
console.log('    - addBasicConstraints() - CA status and path length')
console.log('    - addSubjectAltName() - Alternative names')
console.log('  • Support for both self-signed and CA-signed certificates')
console.log('\nExport certificates using:')
console.log('  • certificate.toPem() - Export as PEM')
console.log('  • certificate.toDer() - Export as DER')
console.log('  • certificate.toString() - View ASN.1 structure')
