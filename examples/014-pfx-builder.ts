// Building a PKCS#12 (PFX) file with certificate and private key

import { PFX } from 'pki-lite/pkcs12/PFX.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== PFX Builder Examples ===\n')

// Generate a key pair for the examples
console.log('Generating RSA key pair...')
const keyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
console.log('✓ Key pair generated\n')

// Create a self-signed certificate
console.log('Creating self-signed certificate...')
const certificate = await Certificate.builder()
    .setSubject('CN=Example User, O=Example Org, C=US')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .selfSign()
console.log('✓ Certificate created\n')

// Example 1: Basic PFX with certificate and private key
console.log('=== Example 1: Basic PFX with Certificate and Private Key ===')
const basicPfx = await PFX.builder()
    .addCertificate(certificate)
    .addPrivateKey(keyPair.privateKey)
    .setPassword('mySecurePassword123')
    .build()

console.log('✓ PFX created')
console.log('  Has MAC data:', !!basicPfx.macData)
console.log('  PFX size:', basicPfx.toDer().length, 'bytes\n')

// Example 2: PFX with friendly name
console.log('=== Example 2: PFX with Friendly Name ===')
const namedPfx = await PFX.builder()
    .addCertificate(certificate)
    .addPrivateKey(keyPair.privateKey)
    .setPassword('mySecurePassword123')
    .setFriendlyName('My Digital Identity')
    .setIterations(100000) // Higher iterations for better security
    .build()

console.log('✓ PFX with friendly name created')
console.log('  Iterations:', namedPfx.macData?.iterations)
console.log('  PFX size:', namedPfx.toDer().length, 'bytes\n')

// Example 3: PFX with certificate chain
console.log('=== Example 3: PFX with Certificate Chain ===')

// Generate a CA key pair
const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })

// Create a CA certificate
const caCert = await Certificate.builder()
    .setSubject('CN=Example CA, O=Example Org, C=US')
    .setPublicKey(caKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true, 2) // CA with pathLen=2
    .addKeyUsage({
        keyCertSign: true,
        cRLSign: true,
    })
    .selfSign()

// Create an end-entity certificate signed by CA
const endEntityKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const endEntityCert = await Certificate.builder()
    .setSubject('CN=End Entity, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(endEntityKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey) // Signed by CA
    .setValidityDays(365)
    .generateSerialNumber()
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .addExtendedKeyUsage({
        clientAuth: true,
        emailProtection: true,
    })
    .build()

// Build PFX with certificate chain
const chainPfx = await PFX.builder()
    .addCertificate(endEntityCert) // End entity cert first
    .addCertificate(caCert) // CA cert for chain
    .addPrivateKey(endEntityKeyPair.privateKey)
    .setPassword('mySecurePassword123')
    .setFriendlyName('My Identity with Chain')
    .setIterations(100000)
    .build()

console.log('✓ PFX with certificate chain created')
console.log('  Certificates in chain: 2')
console.log('  PFX size:', chainPfx.toDer().length, 'bytes\n')

// Example 4: Export and verify PFX
console.log('=== Example 4: Export and Verify PFX ===')

// Export to PEM format
const pfxPem = basicPfx.toPem()
console.log('✓ PFX exported to PEM format')
console.log('  PEM preview:', pfxPem.substring(0, 50) + '...\n')

// Verify by parsing and extracting contents
const password = 'mySecurePassword123'
const parsedPfx = PFX.fromPem(pfxPem)

const extractedCerts = await parsedPfx.getX509Certificates(password)
const extractedKeys = await parsedPfx.getPrivateKeys(password)

console.log('✓ PFX verified successfully')
console.log('  Extracted certificates:', extractedCerts.length)
console.log('  Extracted private keys:', extractedKeys.length)
console.log(
    '  Certificate subject:',
    extractedCerts[0].tbsCertificate.subject.toString(),
)

// Example 5: Using PFX.create() shorthand
console.log('\n=== Example 5: Using PFX.create() Shorthand ===')
const shorthandPfx = await PFX.create({
    certificates: [certificate],
    privateKeys: [keyPair.privateKey],
    password: 'mySecurePassword123',
    friendlyName: 'Quick Identity',
})

console.log('✓ PFX created using shorthand method')
console.log('  PFX size:', shorthandPfx.toDer().length, 'bytes')
