// Creating a CA certificate and issuing end-entity certificates

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Step 1: Generate CA Key Pair ===')
const caKeyPair = await KeyGen.generateRsaPair({ keySize: 4096 })
console.log('✓ CA key pair generated')

console.log('\n=== Step 2: Create CA Certificate (Self-Signed) ===')

// Build and sign the CA certificate
const caCertificate = await Certificate.builder()
    .setSubject('CN=Example CA, O=Example Organization, C=US')
    .setPublicKey(caKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(3650) // 10 years
    .generateSerialNumber()
    .addBasicConstraints(true, 0) // CA with path length 0
    .addKeyUsage({
        keyCertSign: true, // Can sign certificates
        cRLSign: true, // Can sign CRLs
    })
    .selfSign()

console.log('✓ CA certificate created')
console.log('  Subject:', caCertificate.tbsCertificate.subject.toString())
console.log('  Serial:', caCertificate.tbsCertificate.serialNumber.toString())
console.log(
    '  Valid from:',
    caCertificate.tbsCertificate.validity.notBefore.toISOString(),
)
console.log(
    '  Valid until:',
    caCertificate.tbsCertificate.validity.notAfter.toISOString(),
)

console.log('\n=== Step 3: Generate End-Entity Key Pair ===')
const endEntityKeyPair = await KeyGen.generateRsaPair()
console.log('✓ End-entity key pair generated')

console.log('\n=== Step 4: Issue End-Entity Certificate ===')

// Build and sign the end-entity certificate with the CA
const endEntityCertificate = await Certificate.builder()
    .setSubject('CN=example.com, O=Example Organization, C=US')
    .setIssuer(caCertificate) // The CA certificate
    .setPublicKey(endEntityKeyPair.publicKey)
    .setIssuerPrivateKey(caKeyPair.privateKey) // Sign with CA's private key
    .setValidityDays(365) // 1 year
    .generateSerialNumber()
    .addBasicConstraints(false) // Not a CA
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .addExtendedKeyUsage({
        serverAuth: true,
        clientAuth: true,
    })
    .addSubjectAltName('example.com', 'www.example.com', '*.example.com')
    .sign()

console.log('✓ End-entity certificate issued')
console.log(
    '  Subject:',
    endEntityCertificate.tbsCertificate.subject.toString(),
)
console.log('  Issuer:', endEntityCertificate.tbsCertificate.issuer.toString())
console.log(
    '  Serial:',
    endEntityCertificate.tbsCertificate.serialNumber.toString(),
)
console.log(
    '  Valid from:',
    endEntityCertificate.tbsCertificate.validity.notBefore.toISOString(),
)
console.log(
    '  Valid until:',
    endEntityCertificate.tbsCertificate.validity.notAfter.toISOString(),
)

console.log('\n=== Step 5: Verify Certificate Chain ===')
// Verify the signature on the end-entity certificate using the CA's public key
const isValid = await endEntityCertificate.isIssuedBy(caCertificate)
console.log('✓ Certificate chain verification:', isValid ? 'VALID' : 'INVALID')

console.log('\n=== Certificates in PEM Format ===')
console.log('\n--- CA Certificate ---')
console.log(caCertificate.toPem())

console.log('\n--- End-Entity Certificate ---')
console.log(endEntityCertificate.toPem())

console.log('\n--- End-Entity Private Key ---')
console.log(endEntityKeyPair.privateKey.toPem())
