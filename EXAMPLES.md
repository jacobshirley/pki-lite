# PKI-Lite Examples

This directory contains example scripts demonstrating how to use the PKI-Lite library.

## Creating a self-signed certificate

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

## Parsing a PFX and extracting bags, private keys, and certificates

```typescript
import { PFX } from 'pki-lite/pkcs12/PFX.js'

const pem = `-----BEGIN PKCS12-----
{your pfx data here}
-----END PKCS12-----`

const pfx = PFX.fromPem(pem)
console.log('PFX version:', pfx.version)
console.log('Has MAC data:', !!pfx.macData)

const bags = await pfx.getBags('test')
console.log(`Found ${bags.length} bags`)

const privateKeys = await pfx.getPrivateKeys('test')
console.log(`Found ${privateKeys.length} private keys`)
privateKeys.forEach((key, index) => {
    console.log(`Private Key ${index + 1}:`, key.getPrivateKey().toPem())
})

const certificates = await pfx.getX509Certificates('test')
console.log(`Found ${certificates.length} certificates`)
certificates.forEach((cert, index) => {
    console.log(`Certificate ${index + 1}:`, cert.toPem())
})
```

## Creating and parsing a TimeStampReq

```typescript
import { DigestAlgorithmIdentifier } from 'pki-lite/algorithms/AlgorithmIdentifier.js'
import { MessageImprint } from 'pki-lite/timestamp/MessageImprint.js'
import { TimeStampReq } from 'pki-lite/timestamp/TimeStampReq.js'

// 1. Create a message to be timestamped (usually this would be a signature)
const messageToTimestamp = new TextEncoder().encode('Hello, World!')

// 2. Create a hash of the message using SHA-256
const hashBuffer = await crypto.subtle.digest('SHA-256', messageToTimestamp)
const hashBytes = new Uint8Array(hashBuffer)

console.log(
    'Message hash (SHA-256):',
    Array.from(hashBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(''),
)

// 3. Create the MessageImprint
const hashAlgorithm = DigestAlgorithmIdentifier.digestAlgorithm('SHA-256')
const messageImprint = new MessageImprint({
    hashAlgorithm: hashAlgorithm,
    hashedMessage: hashBytes,
})

// 4. Create the TimeStampReq
const nonce = crypto.getRandomValues(new Uint8Array(8)) // Random 8-byte nonce
const tsReq = TimeStampReq.create({
    messageImprint,
    certReq: true, // Request certificates in the response
    nonce: nonce,
})

console.log('TimeStampReq created:')
console.log('- Version:', tsReq.version)
console.log('- Hash Algorithm:', tsReq.messageImprint.hashAlgorithm.algorithm)
console.log('- Certificate Requested:', tsReq.certReq)

// 5. Generate the DER encoding for sending to a TSA server
const derEncoded = tsReq.toDer()
console.log('DER encoded request size:', derEncoded.length, 'bytes')

const response = await tsReq.request({
    url: 'https://freetsa.org/tsr',
    timeout: 10000,
})

console.log('Response status:', response.status.getStatusDescription())

if (response.isSuccess()) {
    console.log('Timestamp token received!')
    const tokenDer = response.getTimeStampTokenDer()
    if (tokenDer) {
        console.log('Token size:', tokenDer.length, 'bytes')
    }
}

// 7. Demonstrate parsing a TimeStampReq from DER
const parsedReq = TimeStampReq.fromDer(derEncoded)
console.log('Parsed request version:', parsedReq.version)
console.log('Parsed request certReq:', parsedReq.certReq)

console.log('TimeStampResp created:')
console.log('- Status:', response.status.getStatusDescription())
console.log('- Success:', response.isSuccess())
console.log('- Has token:', !!response.timeStampToken)

const respDer = response.toDer()
console.log('DER encoded response size:', respDer.length, 'bytes')
```

## Requesting a CRL (using a certificate's CRL distribution points)

```typescript
import { Certificate } from 'pki-lite/x509/Certificate.js'

const certPem = `-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----`
const certificate = Certificate.fromPem(certPem)

// NB: This will only work if the CRL distribution point is accessible
const crl = await certificate.requestCrl()
if (!crl) {
    console.log('No CRL found')
} else {
    console.log('Successfully found CRL', crl.toString())
}
```

## Creating an OCSP request and parsing the response

```typescript
import { Certificate } from 'pki-lite/x509/Certificate.js'

const certPem =
    '-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----'
const issuerCertPem =
    '-----BEGIN CERTIFICATE-----{your issuer certificate here}-----END CERTIFICATE-----'
const certificate = Certificate.fromPem(certPem)

// NB: This will only work if the OCSP responder is accessible
const ocsp = await certificate.requestOcsp({
    issuerCertificate: Certificate.fromPem(issuerCertPem),
})

if (!ocsp) {
    console.log('No OCSP response found')
} else {
    console.log('OCSP Response:', ocsp.toString())
}
```

## Using less common algorithms

```typescript
// Make sure to import the extended crypto module to enable these algorithms
import 'pki-lite-crypto-extended'

import { AlgorithmIdentifier } from 'pki-lite/algorithms/AlgorithmIdentifier.js'

const algorithm = AlgorithmIdentifier.contentEncryptionAlgorithm({
    type: 'SHA1_3DES_3KEY_CBC',
    params: {
        salt: new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]),
        iterationCount: 2048,
    },
})

console.log('Algorithm OID:', algorithm.algorithm.toString())

const toBeEncrypted = new TextEncoder().encode('Hello, World!')
const encrypted = await algorithm.encrypt(
    toBeEncrypted,
    'password', // Can also be a Uint8Array<ArrayBuffer>
)

const decrypted = await algorithm.decrypt(
    encrypted,
    'password', // Can also be a Uint8Array<ArrayBuffer>
)
console.log('Decrypted data:', new TextDecoder().decode(decrypted))
```

## Create a CMS SignedData structure with a signer

```typescript
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { SignedData } from 'pki-lite/pkcs7/SignedData.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

const certPem = `-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----`
const keyPem = `-----BEGIN PRIVATE KEY-----{your private key here}-----END PRIVATE KEY-----`

const certificate = Certificate.fromPem(certPem)
const privateKey = PrivateKeyInfo.fromPem(keyPem)

const signedData = await SignedData.builder()
    .setData(new TextEncoder().encode('Hello, World!'))
    .addCertificate(certificate)
    .addSigner({
        certificate,
        privateKeyInfo: privateKey,
        tsa: {
            url: 'http://timestamp.digicert.com',
        },
    })
    .build()

console.log(signedData.toCms())
```

## Create a CMS EnvelopedData structure with a recipient

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Enveloped Data Example ===\n')

// Generate a key pair and create a certificate for the recipient
console.log('Generating RSA key pair for recipient...')
const keyPair = await KeyGen.generateRsaPair({ keySize: 2048 })

console.log('Creating recipient certificate...')
const certificate = await Certificate.builder()
    .setSubject('CN=Recipient, O=Example Org')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .selfSign()

console.log('✓ Certificate created\n')

// Create enveloped data (encrypted message)
console.log('Creating enveloped data...')
const plaintext = 'Hello, World! This is a secret message.'
const envelopedData = await EnvelopedData.builder()
    .setData(new TextEncoder().encode(plaintext))
    .addRecipient({ certificate })
    .build()

console.log('✓ Enveloped data created')
console.log('\nEnveloped Data (CMS):')
console.log(envelopedData.toCms().toString())

// Decrypt the enveloped data
console.log('\nDecrypting...')
const decrypted = await envelopedData.decrypt(keyPair.privateKey)
console.log('✓ Decrypted successfully')
console.log('Decrypted text:', new TextDecoder().decode(decrypted))
```

## Generating RSA and EC key pairs

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'

// Generate an RSA key pair with 2048-bit key size
console.log('Generating RSA-2048 key pair...')
const rsaKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })

console.log('RSA Private Key (PEM):')
console.log(rsaKeyPair.privateKey.toPem())
console.log('\nRSA Public Key (PEM):')
console.log(rsaKeyPair.publicKey.toPem())

// Generate an ECDSA key pair using P-256 curve
console.log('\n\nGenerating ECDSA P-256 key pair...')
const ecKeyPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })

console.log('EC Private Key (PEM):')
console.log(ecKeyPair.privateKey.toPem())
console.log('\nEC Public Key (PEM):')
console.log(ecKeyPair.publicKey.toPem())

// Generate an ECDSA key pair using P-384 curve
console.log('\n\nGenerating ECDSA P-384 key pair...')
const ecP384KeyPair = await KeyGen.generateEcPair({ namedCurve: 'P-384' })

console.log('EC P-384 Private Key (PEM):')
console.log(ecP384KeyPair.privateKey.toPem())

// You can also extract the raw key objects
const privateKey = rsaKeyPair.privateKey.getPrivateKey()
console.log('\n\nRSA Private Key type:', privateKey.constructor.name)

const ecPrivateKey = ecKeyPair.privateKey.getPrivateKey()
console.log('EC Private Key type:', ecPrivateKey.constructor.name)
```

## Creating a Certificate Signing Request (CSR) / PKCS#10

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { CertificateRequest } from 'pki-lite/x509/CertificateRequest.js'

// Generate a key pair
console.log('Generating RSA key pair...')
const keyPair = await KeyGen.generateRsaPair()
console.log('✓ Key pair generated\n')

// Build and sign the CSR
const csr = await CertificateRequest.builder()
    .setSubject('CN=example.com, O=Example Organization, C=US')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .addExtendedKeyUsage({
        serverAuth: true,
    })
    .addSubjectAltName('example.com', 'www.example.com')
    .build()

// Output the CSR in PEM format
console.log('Certificate Signing Request (PEM):')
console.log(csr.toPem())

// You can also verify the CSR by parsing it back
const parsedCsr = CertificateRequest.fromPem(csr.toPem())
console.log('\n✓ CSR successfully created and parsed')
console.log('Subject:', parsedCsr.requestInfo.subject.toString())
console.log(
    'Signature Algorithm:',
    parsedCsr.signatureAlgorithm.algorithm.toString(),
)
console.log(
    'Number of attributes:',
    parsedCsr.requestInfo.attributes?.length ?? 0,
)
```

## Creating a CA certificate and issuing end-entity certificates

```typescript
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
```

## Certificate chain building and validation

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'

console.log('=== Certificate Chain Validation Example ===\n')

// Generate keys and create a certificate chain for demonstration
console.log('Setting up certificate chain...')

// Generate keys for each level
const rootKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const intermediateKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const endEntityKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })

// Create root CA certificate
const rootCert = await Certificate.builder()
    .setSubject('CN=Root CA, O=Example Root CA, C=US')
    .setPublicKey(rootKeyPair.publicKey)
    .setPrivateKey(rootKeyPair.privateKey)
    .setValidityDays(3650) // 10 years
    .generateSerialNumber()
    .addBasicConstraints(true, 2) // CA with path length 2
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .selfSign()

// Create intermediate CA certificate signed by root
const intermediateCert = await Certificate.builder()
    .setSubject('CN=Intermediate CA, O=Example Intermediate CA, C=US')
    .setIssuer(rootCert.tbsCertificate.subject)
    .setPublicKey(intermediateKeyPair.publicKey)
    .setPrivateKey(rootKeyPair.privateKey) // Signed by root
    .setValidityDays(1825) // 5 years
    .generateSerialNumber()
    .addBasicConstraints(true, 0) // CA with path length 0
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .build()

// Create end-entity certificate signed by intermediate
const endEntityCert = await Certificate.builder()
    .setSubject('CN=www.example.com, O=Example Corp, C=US')
    .setIssuer(intermediateCert.tbsCertificate.subject)
    .setPublicKey(endEntityKeyPair.publicKey)
    .setPrivateKey(intermediateKeyPair.privateKey) // Signed by intermediate
    .setValidityDays(365) // 1 year
    .generateSerialNumber()
    .addBasicConstraints(false) // Not a CA
    .addKeyUsage({ digitalSignature: true, keyEncipherment: true })
    .addExtendedKeyUsage({ serverAuth: true })
    .addSubjectAltName('www.example.com', 'example.com')
    .build()

console.log('✓ Certificate chain created\n')

console.log('Loaded certificates:')
console.log('  Root CA:', rootCert.tbsCertificate.subject.toString())
console.log(
    '  Intermediate CA:',
    intermediateCert.tbsCertificate.subject.toString(),
)
console.log('  End Entity:', endEntityCert.tbsCertificate.subject.toString())

console.log('\n=== Validation 1: Basic Certificate Validation ===')
const validator = new CertificateValidator()

// Validate just the end-entity certificate (without chain validation)
const basicValidation = await validator.validate(endEntityCert, {
    checkSignature: false, // Don't check signature without issuer
})

console.log('Validation Status:', basicValidation.status)
console.log('Is Valid:', basicValidation.isValid)
console.log('Messages:', basicValidation.messages.join(', '))
console.log('Validated At:', basicValidation.validatedAt.toISOString())

console.log('\n=== Validation 2: Certificate Chain Validation ===')

// Validate the full certificate chain
const chainValidation = await validator.validate(endEntityCert, {
    validateChain: true,
    checkSignature: true,
    enforceCAConstraints: true,
    trustAnchors: [
        {
            certificate: rootCert,
        },
    ],
    otherCertificates: [intermediateCert], // Intermediate certificates for chain building
})

console.log('Chain Validation Status:', chainValidation.status)
console.log('Is Valid:', chainValidation.isValid)
console.log('Messages:', chainValidation.messages.join(', '))

if (chainValidation.chain) {
    console.log('\nCertificate Chain:')
    console.log('  Is Complete:', chainValidation.chain.isComplete)
    console.log('  Chain Length:', chainValidation.chain.certificates.length)
    chainValidation.chain.certificates.forEach((cert, index) => {
        console.log(`  [${index}] ${cert.tbsCertificate.subject.toString()}`)
    })
}

console.log('\nDiagnostics:')
console.log(
    '  Steps Performed:',
    chainValidation.diagnostics.stepsPerformed.length,
)
chainValidation.diagnostics.stepsPerformed.forEach((step) => {
    console.log(`    - ${step}`)
})

if (chainValidation.diagnostics.warnings.length > 0) {
    console.log('  Warnings:', chainValidation.diagnostics.warnings.length)
    chainValidation.diagnostics.warnings.forEach((warning) => {
        console.log(`    ! ${warning}`)
    })
}

console.log('\n=== Validation 3: With Custom Validation Time ===')

// Validate with a specific date (useful for checking historical validity)
const historicalDate = new Date('2023-06-01T00:00:00Z')
const historicalValidation = await validator.validate(endEntityCert, {
    validationTime: historicalDate,
    timeTolerance: 300000, // 5 minutes tolerance in milliseconds
})

console.log('Historical Validation Status:', historicalValidation.status)
console.log('Is Valid:', historicalValidation.isValid)
console.log('Validation Time:', historicalDate.toISOString())

console.log('\n=== Validation 4: With Revocation Checking (CRL) ===')

// If you have CRLs available
const crl = await endEntityCert.requestCrl()
if (crl) {
    const crlValidation = await validator.validate(
        endEntityCert,
        {
            checkCRL: true,
        },
        {
            crls: [crl],
            issuerCertificate: intermediateCert,
        },
    )

    console.log('CRL Validation Status:', crlValidation.status)
    console.log('Is Valid:', crlValidation.isValid)
    console.log('Revocation Status:')
    console.log('  Is Revoked:', crlValidation.revocationStatus.isRevoked)
    console.log('  Source:', crlValidation.revocationStatus.source)
    if (crlValidation.revocationStatus.reason !== undefined) {
        console.log('  Reason:', crlValidation.revocationStatus.reason)
    }
} else {
    console.log('No CRL available for this certificate')
}

console.log('\n=== Validation 5: With Name Constraints ===')

// Validate with name constraints (if the CA has name constraints)
const nameConstraintsValidation = await validator.validate(endEntityCert, {
    validateChain: true,
    validateNameConstraints: true,
    trustAnchors: [
        {
            certificate: rootCert,
            // nameConstraints: customNameConstraints, // Add custom constraints if needed
        },
    ],
    otherCertificates: [intermediateCert],
})

console.log(
    'Name Constraints Validation Status:',
    nameConstraintsValidation.status,
)
console.log('Is Valid:', nameConstraintsValidation.isValid)

console.log('\n=== Validation 6: Policy Validation ===')

// Validate with required policies
const policyValidation = await validator.validate(endEntityCert, {
    validateChain: true,
    validatePolicies: true,
    requiredPolicies: ['1.3.6.1.4.1.99999.1.2.3'], // Example policy OID
    trustAnchors: [
        {
            certificate: rootCert,
        },
    ],
    otherCertificates: [intermediateCert],
})

console.log('Policy Validation Status:', policyValidation.status)
console.log('Is Valid:', policyValidation.isValid)
if (policyValidation.policyResult) {
    console.log('Policy Result:')
    console.log('  Is Valid:', policyValidation.policyResult.isValid)
    console.log(
        '  Valid Policies:',
        policyValidation.policyResult.validPolicies,
    )
    console.log('  Violations:', policyValidation.policyResult.violations)
}

console.log('\n=== Certificate Information ===')

// Extract useful information from a certificate
console.log('\nEnd Entity Certificate Details:')
console.log('  Version:', endEntityCert.tbsCertificate.version + 1) // Version is 0-indexed
console.log(
    '  Serial Number:',
    endEntityCert.tbsCertificate.serialNumber.toString(),
)
console.log('  Subject:', endEntityCert.tbsCertificate.subject.toString())
console.log('  Issuer:', endEntityCert.tbsCertificate.issuer.toString())
console.log(
    '  Not Before:',
    endEntityCert.tbsCertificate.validity.notBefore.toISOString(),
)
console.log(
    '  Not After:',
    endEntityCert.tbsCertificate.validity.notAfter.toISOString(),
)
console.log(
    '  Signature Algorithm:',
    endEntityCert.signatureAlgorithm.algorithm.toString(),
)

if (endEntityCert.tbsCertificate.extensions) {
    console.log('  Extensions:', endEntityCert.tbsCertificate.extensions.length)
    endEntityCert.tbsCertificate.extensions.forEach((ext) => {
        console.log(`    - ${ext.extnID.value} (Critical: ${ext.critical})`)
    })
}
```

## Using the Certificate Builder for flexible certificate creation

```typescript
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
```

## Building a PKCS#12 (PFX) file with certificate and private key

```typescript
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
```

## Building encrypted data using the EncryptedData builder

```typescript
import { EncryptedData } from 'pki-lite/pkcs7/EncryptedData.js'
import { OIDs } from 'pki-lite/core/OIDs.js'
import { getCryptoProvider } from 'pki-lite/core/crypto/provider.js'

console.log('=== EncryptedData Builder Examples ===\n')

const secretMessage = new TextEncoder().encode(
    'This is a secret message that needs to be encrypted!',
)
const password = 'mySecurePassword123'

// Example 1: Basic encryption with default settings (PBES2)
console.log('=== Example 1: Basic Encryption with Default Settings ===')
const basicEncrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .build()

console.log('✓ Data encrypted with default PBES2 algorithm')
console.log('  Version:', basicEncrypted.version)
console.log(
    '  Content type:',
    basicEncrypted.encryptedContentInfo.contentType.value,
)
console.log(
    '  Encrypted size:',
    basicEncrypted.encryptedContentInfo.encryptedContent?.bytes.length,
    'bytes',
)
console.log(
    '  Algorithm:',
    basicEncrypted.encryptedContentInfo.contentEncryptionAlgorithm.friendlyName,
)

// Decrypt to verify
const provider = getCryptoProvider()
const algorithm1 = provider.toSymmetricEncryptionAlgorithmParams(
    basicEncrypted.encryptedContentInfo.contentEncryptionAlgorithm,
)
const decrypted1 = await provider.decryptSymmetric(
    basicEncrypted.encryptedContentInfo.encryptedContent!.bytes,
    password as any, // Type definitions need updating to accept string
    algorithm1,
)
console.log('✓ Decrypted successfully:', new TextDecoder().decode(decrypted1))
console.log()

// Example 2: Encryption with custom PBKDF2 iterations
console.log('=== Example 2: Custom Iterations for PBKDF2 ===')
const customIterations = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .setAlgorithm({
        type: 'PBES2',
        params: {
            derivationAlgorithm: {
                type: 'PBKDF2',
                params: {
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    iterationCount: 100000, // Higher security
                    hash: 'SHA-256',
                },
            },
            encryptionAlgorithm: {
                type: 'AES_256_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            },
        },
    })
    .build()

console.log('✓ Data encrypted with 100,000 PBKDF2 iterations')
console.log(
    '  Algorithm:',
    customIterations.encryptedContentInfo.contentEncryptionAlgorithm
        .friendlyName,
)
console.log()

// Example 3: Encryption with SHA-512 hash
console.log('=== Example 3: Using SHA-512 for Key Derivation ===')
const sha512Encrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .setAlgorithm({
        type: 'PBES2',
        params: {
            derivationAlgorithm: {
                type: 'PBKDF2',
                params: {
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    iterationCount: 50000,
                    hash: 'SHA-512', // More secure hash
                },
            },
            encryptionAlgorithm: {
                type: 'AES_256_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            },
        },
    })
    .build()

console.log('✓ Data encrypted using SHA-512 for key derivation')
console.log(
    '  Algorithm:',
    sha512Encrypted.encryptedContentInfo.contentEncryptionAlgorithm
        .friendlyName,
)
console.log()

// Example 4: Encryption with AES-128 (smaller key size)
console.log('=== Example 4: Using AES-128-CBC ===')
const aes128Encrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .setAlgorithm({
        type: 'PBES2',
        params: {
            derivationAlgorithm: {
                type: 'PBKDF2',
                params: {
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    iterationCount: 10000,
                    hash: 'SHA-256',
                },
            },
            encryptionAlgorithm: {
                type: 'AES_128_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            },
        },
    })
    .build()

console.log('✓ Data encrypted with AES-128-CBC')
console.log()

// Example 5: Using EncryptedData.create() shorthand
console.log('=== Example 5: Using EncryptedData.create() Shorthand ===')
const shorthand = await EncryptedData.create({
    contentType: 'DATA',
    data: secretMessage,
    password,
    iterations: 50000,
})

console.log('✓ Data encrypted using shorthand method')
console.log('  Encrypted size:', shorthand.toDer().length, 'bytes')
console.log()

// Example 6: Export to DER and convert to CMS
console.log('=== Example 6: Export and Convert to CMS ===')
const der = basicEncrypted.toDer()
console.log('✓ Encrypted data exported to DER')
console.log('  DER size:', der.length, 'bytes')

// Convert to CMS ContentInfo
const cms = basicEncrypted.asCms()
console.log('✓ Converted to CMS ContentInfo')
console.log('  Content type:', cms.contentType.value)
console.log('  CMS size:', cms.toDer().length, 'bytes')
```

## Building a Certificate Revocation List (CRL) using the CertificateList builder

```typescript
import { CertificateList } from 'pki-lite/x509/CertificateList.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { Extension } from 'pki-lite/x509/Extension.js'
import { OIDs } from 'pki-lite/core/OIDs.js'

console.log('=== CRL Builder Examples ===\n')

// First, create a CA certificate and key pair
console.log('Setting up CA...')
const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const caCert = await Certificate.builder()
    .setSubject('CN=Example CA, O=Example Org, C=US')
    .setPublicKey(caKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true, 2)
    .addKeyUsage({
        keyCertSign: true,
        cRLSign: true,
    })
    .selfSign()
console.log('✓ CA certificate created\n')

// Create some end-entity certificates to revoke
console.log('Creating certificates to revoke...')
const cert1KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const cert1 = await Certificate.builder()
    .setSubject('CN=User 1, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(cert1KeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .setSerialNumber(1001)
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .build()

const cert2KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const cert2 = await Certificate.builder()
    .setSubject('CN=User 2, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(cert2KeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .setSerialNumber(1002)
    .addKeyUsage({
        digitalSignature: true,
        keyEncipherment: true,
    })
    .build()

console.log('✓ Test certificates created\n')

// Example 1: Basic CRL with revoked certificates
console.log('=== Example 1: Basic CRL with Revoked Certificates ===')
const basicCrl = await CertificateList.builder()
    .setIssuerFromCertificate(caCert)
    .setPrivateKey(caKeyPair.privateKey)
    .setThisUpdate(new Date())
    .setNextUpdate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)) // 30 days
    .addRevokedCertificate({
        serialNumber: 1001,
        revocationDate: new Date(),
    })
    .addRevokedCertificate({
        serialNumber: 1002,
        revocationDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
    })
    .build()

console.log('✓ Basic CRL created')
console.log('  Issuer:', basicCrl.tbsCertList.issuer.toString())
console.log('  This Update:', basicCrl.tbsCertList.thisUpdate)
console.log('  Next Update:', basicCrl.tbsCertList.nextUpdate)
console.log(
    '  Revoked Certificates:',
    basicCrl.tbsCertList.revokedCertificates?.length || 0,
)
console.log('  CRL size:', basicCrl.toDer().length, 'bytes\n')

// Example 2: Revoking certificates by reference
console.log('=== Example 2: Revoking Certificates by Reference ===')
const referenceCrl = await CertificateList.builder()
    .setIssuerFromCertificate(caCert)
    .setPrivateKey(caKeyPair.privateKey)
    .revokeCertificate(cert1) // Revokes using current time
    .revokeCertificate(cert2, new Date(Date.now() - 14 * 24 * 60 * 60 * 1000)) // 14 days ago
    .build()

console.log('✓ CRL created by revoking certificate references')
console.log(
    '  Revoked Certificates:',
    referenceCrl.tbsCertList.revokedCertificates?.length || 0,
)
console.log()

// Example 3: CRL with CRL Number extension
console.log('=== Example 3: CRL with CRL Number Extension ===')
const crlNumberExtension = new Extension({
    extnID: OIDs.EXTENSION.CRL_NUMBER,
    critical: false,
    extnValue: new Uint8Array([0x02, 0x01, 0x01]), // Integer 1 (ASN.1 DER encoded)
})

const numberedCrl = await CertificateList.builder()
    .setIssuerFromCertificate(caCert)
    .setPrivateKey(caKeyPair.privateKey)
    .addExtension(crlNumberExtension)
    .revokeCertificate(cert1)
    .build()

console.log('✓ CRL with CRL Number extension created')
console.log('  Extensions:', numberedCrl.tbsCertList.extensions?.length || 0)
console.log(
    '  CRL version:',
    numberedCrl.tbsCertList.version === 1 ? 'v2' : 'v1',
)
console.log()

// Example 4: Empty CRL (no revoked certificates)
console.log('=== Example 4: Empty CRL ===')
const emptyCrl = await CertificateList.builder()
    .setIssuerFromCertificate(caCert)
    .setPrivateKey(caKeyPair.privateKey)
    .setThisUpdate(new Date())
    .setNextUpdate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)) // 7 days
    .build()

console.log('✓ Empty CRL created (no revoked certificates)')
console.log(
    '  Revoked Certificates:',
    emptyCrl.tbsCertList.revokedCertificates?.length || 0,
)
console.log('  CRL version:', emptyCrl.tbsCertList.version === 1 ? 'v2' : 'v1')
console.log()

// Example 5: Export and parse CRL
console.log('=== Example 5: Export and Parse CRL ===')

// Export to PEM
const crlPem = basicCrl.toPem()
console.log('✓ CRL exported to PEM format')
console.log('  PEM preview:', crlPem.substring(0, 50) + '...')

// Parse back from PEM
const parsedCrl = CertificateList.fromPem(crlPem)
console.log('✓ CRL parsed from PEM')
console.log(
    '  Issuer matches:',
    parsedCrl.tbsCertList.issuer.toString() ===
        basicCrl.tbsCertList.issuer.toString(),
)
console.log(
    '  Revoked count matches:',
    parsedCrl.tbsCertList.revokedCertificates?.length ===
        basicCrl.tbsCertList.revokedCertificates?.length,
)
console.log()

// Example 6: Checking if a certificate is revoked
console.log('=== Example 6: Checking Revocation Status ===')
const serialToCheck = cert1.tbsCertificate.serialNumber.toString()
const isRevoked = basicCrl.tbsCertList.revokedCertificates?.some(
    (revoked) => revoked.userCertificate.toString() === serialToCheck,
)

console.log(
    `Certificate with serial ${serialToCheck}:`,
    isRevoked ? 'REVOKED' : 'Valid',
)

if (isRevoked) {
    const revokedEntry = basicCrl.tbsCertList.revokedCertificates?.find(
        (revoked) => revoked.userCertificate.toString() === serialToCheck,
    )
    console.log('  Revocation Date:', revokedEntry?.revocationDate)
}
```

## Building OCSP responses using the OCSPResponse builder

```typescript
import { OCSPResponse } from 'pki-lite/ocsp/OCSPResponse.js'
import { CertID } from 'pki-lite/ocsp/CertID.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { OCSPResponseStatus } from 'pki-lite/ocsp/OCSPResponseStatus.js'

console.log('=== OCSP Response Builder Examples ===\n')

// Setup: Create CA and certificates
console.log('Setting up CA and certificates...')
const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const caCert = await Certificate.builder()
    .setSubject('CN=OCSP CA, O=Example Org, C=US')
    .setPublicKey(caKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true, 2)
    .addKeyUsage({
        keyCertSign: true,
        cRLSign: true,
    })
    .selfSign()

// Create an OCSP responder key
const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const responderCert = await Certificate.builder()
    .setSubject('CN=OCSP Responder, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(responderKeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .addKeyUsage({
        digitalSignature: true,
    })
    .addExtendedKeyUsage({
        ocspSigning: true,
    })
    .build()

// Create some end-entity certificates
const cert1KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const cert1 = await Certificate.builder()
    .setSubject('CN=User 1, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(cert1KeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .setSerialNumber(2001)
    .build()

const cert2KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const cert2 = await Certificate.builder()
    .setSubject('CN=User 2, O=Example Org, C=US')
    .setIssuer(caCert.tbsCertificate.subject)
    .setPublicKey(cert2KeyPair.publicKey)
    .setPrivateKey(caKeyPair.privateKey)
    .setValidityDays(365)
    .setSerialNumber(2002)
    .build()

console.log('✓ Setup complete\n')

// Example 1: Basic OCSP response with good status (using Certificate directly)
console.log('=== Example 1: Basic OCSP Response (Good Status) ===')

const goodResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert1, 'good') // Pass issuer and certificate!
    .build()

console.log('✓ OCSP response created with good status')
console.log('  Response Status:', goodResponse.responseStatus.value)
const basicResp1 = goodResponse.getBasicOCSPResponse()
console.log('  Responses:', basicResp1.tbsResponseData.responses.length)
console.log(
    '  Certificate Status:',
    basicResp1.tbsResponseData.responses[0].certStatus.status,
)
console.log('  Response size:', goodResponse.toDer().length, 'bytes\n')

// Example 2: OCSP response with revoked status
console.log('=== Example 2: OCSP Response with Revoked Status ===')
const revocationDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // 7 days ago

const revokedResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert2, 'revoked', {
        revocationTime: revocationDate,
        revocationReason: 0, // unspecified reason
    })
    .build()

console.log('✓ OCSP response created with revoked status')
const basicResp2 = revokedResponse.getBasicOCSPResponse()
console.log(
    '  Certificate Status:',
    basicResp2.tbsResponseData.responses[0].certStatus.status,
)
console.log(
    '  Revocation Time:',
    basicResp2.tbsResponseData.responses[0].certStatus.revocationTime,
)
console.log()

// Example 3: Multiple certificate responses in one OCSP response
console.log('=== Example 3: Multiple Certificate Responses ===')
const multiResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert1, 'good') // Add multiple responses!
    .addResponse(caCert, cert2, 'revoked', {
        revocationTime: revocationDate,
        revocationReason: 0,
    })
    .build()

console.log('✓ OCSP response with multiple certificates created')
const basicResp3 = multiResponse.getBasicOCSPResponse()
console.log('  Total responses:', basicResp3.tbsResponseData.responses.length)
console.log(
    '  Response 1 status:',
    basicResp3.tbsResponseData.responses[0].certStatus.status,
)
console.log(
    '  Response 2 status:',
    basicResp3.tbsResponseData.responses[1].certStatus.status,
)
console.log()

// Example 4: OCSP response with custom validity period
console.log('=== Example 4: Custom Validity Period ===')
const now = new Date()
const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000)
const nextWeek = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000)

const customValidityResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .setProducedAt(now)
    .addResponse(caCert, cert1, 'good', {
        thisUpdate: tomorrow,
        nextUpdate: nextWeek,
    })
    .build()

console.log('✓ OCSP response with custom validity created')
const basicResp4 = customValidityResponse.getBasicOCSPResponse()
console.log('  Produced At:', basicResp4.tbsResponseData.producedAt)
console.log(
    '  This Update:',
    basicResp4.tbsResponseData.responses[0].thisUpdate.time,
)
console.log(
    '  Next Update:',
    basicResp4.tbsResponseData.responses[0].nextUpdate?.time,
)
console.log()

// Example 5: OCSP response with responder certificate included
console.log('=== Example 5: Including Responder Certificate ===')
const withCertResponse = await OCSPResponse.builder()
    .setResponderFromCertificate(responderCert)
    .setPrivateKey(responderKeyPair.privateKey)
    .addResponse(caCert, cert1, 'good')
    .addCertificate(responderCert) // Include responder cert for validation
    .build()

console.log('✓ OCSP response with responder certificate created')
const basicResp5 = withCertResponse.getBasicOCSPResponse()
console.log('  Included certificates:', basicResp5.certs?.length || 0)
if (basicResp5.certs && basicResp5.certs.length > 0) {
    console.log(
        '  Responder cert subject:',
        basicResp5.certs[0].tbsCertificate.subject.toString(),
    )
}
console.log()

// Example 6: Error response (no signature required)
console.log('=== Example 6: Error Response ===')
const errorResponse = await OCSPResponse.builder()
    .setResponseStatus(OCSPResponseStatus.malformedRequest)
    .build()

console.log('✓ Error response created')
console.log('  Response Status:', errorResponse.responseStatus.value)
console.log('  Has response bytes:', !!errorResponse.responseBytes)
console.log()

// Example 7: Using OCSPResponse.forCertificate() shorthand
console.log('=== Example 7: Using forCertificate() Shorthand ===')
const shorthandResponse = await OCSPResponse.forCertificate({
    issuerCertificate: caCert,
    subjectCertificate: cert1,
    privateKey: responderKeyPair.privateKey,
    responderID: responderCert.tbsCertificate.subject,
})

console.log('✓ OCSP response created using shorthand method')
console.log('  Response Status:', shorthandResponse.responseStatus.value)
console.log('  Response size:', shorthandResponse.toDer().length, 'bytes')
console.log()

// Example 8: Export and parse OCSP response
console.log('=== Example 8: Export and Parse OCSP Response ===')
const der = goodResponse.toDer()
console.log('✓ OCSP response exported to DER')
console.log('  DER size:', der.length, 'bytes')

const parsed = OCSPResponse.fromDer(der)
console.log('✓ OCSP response parsed from DER')
console.log(
    '  Status matches:',
    parsed.responseStatus.value === goodResponse.responseStatus.value,
)
```

## Authenticated encryption with CMS AuthEnvelopedData (AES-GCM)

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { der } from 'pki-lite/core/PkiBase.js'
import { AuthEnvelopedData } from 'pki-lite/pkcs7/AuthEnvelopedData.js'
import { Attribute } from 'pki-lite/x509/Attribute.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== AuthEnvelopedData Example ===\n')

// The recipient: an RSA key pair and a certificate
const keyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const certificate = await Certificate.builder()
    .setSubject('CN=Recipient, O=Example Org')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .selfSign()

// Encrypt. Unlike EnvelopedData, the content is encrypted with AES-GCM, so any change
// to it is detected on decryption. The default is AES-256-GCM with a 16-byte tag.
const message = 'Confidential and tamper-evident'
const authEnvelopedData = await AuthEnvelopedData.builder()
    .setData(message)
    .addRecipient({ certificate })
    .build()

const cipher = authEnvelopedData.authEncryptedContentInfo
console.log('Cipher:', cipher.contentEncryptionAlgorithm.algorithm.friendlyName)
console.log('Ciphertext bytes:', cipher.encryptedContent?.bytes.length)
console.log('Authentication tag (mac) bytes:', authEnvelopedData.mac.length)

// Send it as DER (this is what `openssl cms -decrypt -inform DER` reads) ...
const encoded = authEnvelopedData.toCms().toDer()
console.log('CMS size:', encoded.length, 'bytes')

// ... and the recipient parses and decrypts it
const received = AuthEnvelopedData.fromCms(encoded)
const plaintext = await received.decrypt(keyPair.privateKey)
console.log('Decrypted:', new TextDecoder().decode(plaintext))

// Tampering is detected: flipping one bit of the ciphertext or the tag makes
// decryption fail instead of returning altered data.
const tampered = AuthEnvelopedData.fromCms(encoded)
tampered.mac[0] ^= 1
try {
    await tampered.decrypt(keyPair.privateKey)
    console.log('Tampering was NOT detected (unexpected)')
} catch {
    console.log('Tampered message rejected: authentication failed')
}

// Authenticated attributes travel with the message and are covered by the tag, so they
// cannot be altered either. (A content-type attribute is added automatically.)
const withAttributes = await AuthEnvelopedData.builder()
    .setData('Message with authenticated metadata')
    .addAuthenticatedAttribute(
        new Attribute({
            type: '1.2.3.4.5', // an application-specific OID
            values: [der.integer(42)],
        }),
    )
    .addRecipient({ certificate })
    .build()

console.log(
    '\nAuthenticated attributes:',
    [...(withAttributes.authAttrs ?? [])].map((attribute) =>
        attribute.type.toString(),
    ),
)
console.log(
    'Decrypted:',
    new TextDecoder().decode(await withAttributes.decrypt(keyPair.privateKey)),
)

// Choose the cipher and tag length yourself: AES-128-GCM with a 12-byte tag
const compact = await AuthEnvelopedData.builder()
    .setData('Shorter tag, smaller key')
    .setContentEncryptionAlgorithm({
        type: 'AES_128_GCM',
        params: {
            nonce: crypto.getRandomValues(new Uint8Array(12)),
            icvLen: 12, // tag length in bytes (12 to 16)
        },
    })
    .addRecipient({ certificate })
    .build()
console.log(
    '\nAES-128-GCM, tag bytes:',
    compact.mac.length,
    '->',
    new TextDecoder().decode(await compact.decrypt(keyPair.privateKey)),
)
```

## Protecting a private key with a password (PKCS#8 EncryptedPrivateKeyInfo)

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { EncryptedPrivateKeyInfo } from 'pki-lite/keys/EncryptedPrivateKeyInfo.js'

console.log('=== Encrypted Private Key Example ===\n')

const { privateKey } = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
console.log('Plain PKCS#8 PEM header:', privateKey.toPem().split('\n')[0])

// Encrypt with a password using PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC)
const password = 'correct horse battery staple'
const encrypted = await EncryptedPrivateKeyInfo.create(privateKey, password, {
    iterations: 100_000, // more iterations make password guessing slower
})

// The PEM can be stored or shared: `openssl pkey -in key.pem` reads it
const pem = encrypted.toPem()
console.log('\nEncrypted PEM:')
console.log(pem)

// Load it back and decrypt
const loaded = EncryptedPrivateKeyInfo.fromPem(pem)
const decrypted = await loaded.decrypt(password)
console.log(
    '\nDecrypted key matches the original:',
    decrypted.equals(privateKey),
)

// A wrong password fails instead of returning garbage
try {
    await loaded.decrypt('wrong password')
    console.log('Wrong password was accepted (unexpected)')
} catch {
    console.log('Wrong password rejected')
}
```

## Reading certificate extensions

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { OIDs } from 'pki-lite/core/OIDs.js'
import { SubjectKeyIdentifier } from 'pki-lite/keys/SubjectKeyIdentifier.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { BasicConstraints } from 'pki-lite/x509/extensions/BasicConstraints.js'
import { ExtKeyUsage } from 'pki-lite/x509/extensions/ExtKeyUsage.js'
import { KeyUsage } from 'pki-lite/x509/extensions/KeyUsage.js'
import { GeneralName } from 'pki-lite/x509/GeneralName.js'

console.log('=== Certificate Extensions Example ===\n')

// A certificate with a typical set of extensions (any certificate would do)
const keyPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
const certificate = await Certificate.builder()
    .setSubject('CN=www.example.com, O=Example Org, C=GB')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setAlgorithm({
        type: 'ECDSA',
        params: { namedCurve: 'P-256', hash: 'SHA-256' },
    })
    .setValidityDays(90)
    .generateSerialNumber()
    .addBasicConstraints(false)
    .addKeyUsage({ digitalSignature: true })
    .addExtendedKeyUsage({ serverAuth: true, clientAuth: true })
    .addSubjectAltName(
        'www.example.com',
        'example.com',
        new GeneralName.rfc822Name({ value: 'admin@example.com' }),
        new GeneralName.iPAddress({ bytes: new Uint8Array([192, 0, 2, 1]) }),
    )
    .addSubjectKeyIdentifier(crypto.getRandomValues(new Uint8Array(20)))
    .selfSign()

// Every extension, with its OID and whether it is critical
console.log('Extensions present:')
for (const extension of certificate.tbsCertificate.extensions ?? []) {
    console.log(
        `  ${extension.extnID.friendlyName} (${extension.extnID})`,
        extension.critical ? '[critical]' : '',
    )
}

// Look one up by OID and parse its value as the matching class
const basicConstraints = certificate
    .getExtensionByOid(OIDs.EXTENSION.BASIC_CONSTRAINTS)
    ?.extnValue.parseAs(BasicConstraints)
console.log('\nIs a CA:', basicConstraints?.cA)

const keyUsage = certificate
    .getExtensionByOid(OIDs.EXTENSION.KEY_USAGE)
    ?.extnValue.parseAs(KeyUsage)
console.log(
    'Key usage:',
    Object.entries(keyUsage ?? {})
        .filter(([, set]) => set === true)
        .map(([name]) => name),
)

const extKeyUsage = certificate
    .getExtensionByOid(OIDs.EXTENSION.EXTENDED_KEY_USAGE)
    ?.extnValue.parseAs(ExtKeyUsage)
console.log(
    'Extended key usage:',
    [...(extKeyUsage ?? [])].map((oid) => oid.friendlyName),
)

const keyIdentifier = certificate
    .getExtensionByOid(OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER)
    ?.extnValue.parseAs(SubjectKeyIdentifier)
console.log('Subject key identifier:', keyIdentifier?.toHumanString())

// Subject alternative names: each entry is a typed GeneralName
console.log('\nSubject alternative names:')
for (const alternativeNames of certificate.getSubjectAltNames()) {
    for (const name of alternativeNames) {
        const value =
            name instanceof GeneralName.iPAddress
                ? [...name.bytes].join('.') // an IPv4 address is 4 raw bytes
                : name.toString()
        console.log(`  ${name.constructor.name}: ${value}`)
    }
}
console.log('Common name:', certificate.getCommonName())
```

## Restricting a CA with name constraints

```typescript
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { Extension } from 'pki-lite/x509/Extension.js'
import {
    GeneralSubtree,
    NameConstraints,
} from 'pki-lite/x509/extensions/NameConstraints.js'
import { dNSName } from 'pki-lite/x509/GeneralName.js'

console.log('=== Name Constraints Example ===\n')

// A CA that may only issue for example.com and its subdomains, except secret.example.com
const nameConstraints = new NameConstraints({
    permittedSubtrees: [
        new GeneralSubtree({ base: new dNSName({ value: 'example.com' }) }),
    ],
    excludedSubtrees: [
        new GeneralSubtree({
            base: new dNSName({ value: 'secret.example.com' }),
        }),
    ],
})

const caKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const caCertificate = await Certificate.builder()
    .setSubject('CN=Constrained CA, O=Example Org')
    .setPublicKey(caKeys.publicKey)
    .setPrivateKey(caKeys.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .addExtension(
        new Extension({
            extnID: '2.5.29.30', // id-ce-nameConstraints
            critical: true,
            extnValue: nameConstraints,
        }),
    )
    .selfSign()
console.log('Created CA with name constraints\n')

// The constraints can be read back from the certificate and checked directly
const constraints = caCertificate
    .getExtensionByOid('2.5.29.30')!
    .extnValue.parseAs(NameConstraints)
for (const name of ['www.example.com', 'www.evil.com', 'secret.example.com']) {
    const permitted = constraints.permittedSubtrees?.matches(name) ?? true
    const excluded = constraints.excludedSubtrees?.matches(name) ?? false
    console.log(
        `${name.padEnd(20)} permitted: ${permitted}, excluded: ${excluded}`,
    )
}

// Issue a certificate for each name and let the validator apply the constraints
console.log('\nValidating issued certificates:')
const validator = new CertificateValidator()
for (const host of ['www.example.com', 'www.evil.com', 'secret.example.com']) {
    const keys = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
    const certificate = await Certificate.builder()
        .setSubject(`CN=${host}`)
        .setIssuer(caCertificate)
        .setPublicKey(keys.publicKey)
        .setIssuerPrivateKey(caKeys.privateKey)
        .setValidityDays(30)
        .generateSerialNumber()
        .addBasicConstraints(false)
        .addSubjectAltName(host)
        .sign()

    const result = await validator.validate(certificate, {
        validateChain: true,
        validateNameConstraints: true,
        // The constraints in the CA certificate itself are enforced. (They can also be
        // given with the trust anchor: `{ certificate, nameConstraints }`.)
        trustAnchors: [{ certificate: caCertificate }],
    })
    console.log(`  ${host.padEnd(20)} valid: ${result.isValid}`)
    if (!result.isValid) {
        console.log(`    ${result.messages.join('; ')}`)
    }
}
```

## Creating and verifying a detached CMS signature

```typescript
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { ContentInfo } from 'pki-lite/pkcs7/ContentInfo.js'
import { SignedData } from 'pki-lite/pkcs7/SignedData.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Signed Data Verification Example ===\n')

// A CA and a signer certificate issued by it
const caKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const caCertificate = await Certificate.builder()
    .setSubject('CN=Example Signing CA')
    .setPublicKey(caKeys.publicKey)
    .setPrivateKey(caKeys.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true })
    .selfSign()

const signerKeys = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
const signerCertificate = await Certificate.builder()
    .setSubject('CN=Alice, O=Example Org')
    .setIssuer(caCertificate)
    .setPublicKey(signerKeys.publicKey)
    .setIssuerPrivateKey(caKeys.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .addBasicConstraints(false)
    .addKeyUsage({ digitalSignature: true })
    .sign()

// Sign a document. A detached signature keeps the document out of the CMS structure.
const document = new TextEncoder().encode('Invoice #1234: pay 100 EUR')
const signedData = await SignedData.builder()
    .setData(document)
    .setDetached(true)
    .addCertificate(signerCertificate)
    .addSigner({
        certificate: signerCertificate,
        privateKeyInfo: signerKeys.privateKey,
        // the default is RSA, so say which algorithm an EC key signs with
        encryptionAlgorithm: {
            type: 'ECDSA',
            params: { namedCurve: 'P-256', hash: 'SHA-256' },
        },
    })
    .build()

const der = signedData.toCms().toDer()
console.log('Detached signature:', der.length, 'bytes (document not included)')

// Verify: parse the signature and supply the document it belongs to
const received = ContentInfo.fromDer(der).parseContentAs(SignedData)
const result = await received.verify({ data: document })
console.log('\nSignature valid:', result.valid)
if (result.valid) {
    console.log('Signer:', result.signerInfo.sid.toHumanString())
}

// Any change to the document breaks the signature
const forged = await received.verify({
    data: new TextEncoder().encode('Invoice #1234: pay 900 EUR'),
})
console.log('\nAltered document valid:', forged.valid)
if (!forged.valid) {
    console.log('Reason:', forged.reasons[0])
}

// The signature above proves *who* signed only if you trust the signer's certificate.
// Ask the verifier to also validate the signer's chain against a trusted CA:
const trusted = await received.verify({
    data: document,
    certificateValidation: {
        validateChain: true,
        trustAnchors: [{ certificate: caCertificate }],
    },
})
console.log('\nSigned by a trusted CA:', trusted.valid)

const untrusted = await received.verify({
    data: document,
    certificateValidation: {
        validateChain: true,
        trustAnchors: [
            {
                // some unrelated CA
                certificate: await (async () => {
                    const keys = await KeyGen.generateRsaPair({ keySize: 2048 })
                    return Certificate.builder()
                        .setSubject('CN=Some Other CA')
                        .setPublicKey(keys.publicKey)
                        .setPrivateKey(keys.privateKey)
                        .setValidityDays(30)
                        .generateSerialNumber()
                        .addBasicConstraints(true)
                        .selfSign()
                })(),
            },
        ],
    },
})
console.log('Signed by an unrelated CA:', untrusted.valid)

// The validator can also be used on its own
const chain = await new CertificateValidator().validate(signerCertificate, {
    validateChain: true,
    trustAnchors: [{ certificate: caCertificate }],
})
console.log('\nSigner certificate status:', chain.status)
```

## Choosing signature algorithms: RSA, RSA-PSS, ECDSA and Ed25519

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from 'pki-lite/keys/SubjectPublicKeyInfo.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Signature Algorithms Example ===\n')

async function selfSigned(
    name: string,
    keys: { privateKey: PrivateKeyInfo; publicKey: SubjectPublicKeyInfo },
    algorithm: Parameters<
        ReturnType<typeof Certificate.builder>['setAlgorithm']
    >[0],
) {
    const certificate = await Certificate.builder()
        .setSubject(`CN=${name}`)
        .setPublicKey(keys.publicKey)
        .setPrivateKey(keys.privateKey)
        .setAlgorithm(algorithm)
        .setValidityDays(30)
        .generateSerialNumber()
        .selfSign()

    // Check the signature we just made, and report what was used
    const valid = await certificate.isSelfSigned()
    console.log(
        `${name.padEnd(22)} ${certificate.signatureAlgorithm.algorithm.friendlyName}`.padEnd(
            58,
        ),
        `signature valid: ${valid}`,
    )
}

// RSA: the classic PKCS#1 v1.5 padding, or the newer, randomised PSS
const rsa = await KeyGen.generateRsaPair({ keySize: 2048 })
await selfSigned('RSA PKCS#1 v1.5', rsa, {
    type: 'RSASSA_PKCS1_v1_5',
    params: { hash: 'SHA-256' },
})
await selfSigned('RSA-PSS', rsa, {
    type: 'RSA_PSS',
    params: { hash: 'SHA-256', saltLength: 32 },
})

// ECDSA: the hash is chosen independently of the curve
const p256 = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
await selfSigned('ECDSA P-256 / SHA-256', p256, {
    type: 'ECDSA',
    params: { namedCurve: 'P-256', hash: 'SHA-256' },
})
const p384 = await KeyGen.generateEcPair({ namedCurve: 'P-384' })
await selfSigned('ECDSA P-384 / SHA-384', p384, {
    type: 'ECDSA',
    params: { namedCurve: 'P-384', hash: 'SHA-384' },
})

// Ed25519 has no hash or other parameters. KeyGen does not generate these keys yet, so
// create one with WebCrypto (needs a runtime that supports Ed25519) and wrap it.
const ed25519 = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
])
await selfSigned(
    'Ed25519',
    {
        privateKey: PrivateKeyInfo.fromDer(
            new Uint8Array(
                await crypto.subtle.exportKey('pkcs8', ed25519.privateKey),
            ),
        ),
        publicKey: SubjectPublicKeyInfo.fromDer(
            new Uint8Array(
                await crypto.subtle.exportKey('spki', ed25519.publicKey),
            ),
        ),
    },
    { type: 'ED25519', params: {} },
)
```

## Inspecting ASN.1, and converting between PEM and DER

```typescript
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { ObjectIdentifier } from 'pki-lite/asn1/ObjectIdentifier.js'
import { derToAsn1 } from 'pki-lite/core/PkiBase.js'
import { ContentInfo } from 'pki-lite/pkcs7/ContentInfo.js'
import { SignedData } from 'pki-lite/pkcs7/SignedData.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== ASN.1 and PEM Example ===\n')

const keys = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
const certificate = await Certificate.builder()
    .setSubject('CN=ASN.1 Example')
    .setPublicKey(keys.publicKey)
    .setPrivateKey(keys.privateKey)
    .setAlgorithm({
        type: 'ECDSA',
        params: { namedCurve: 'P-256', hash: 'SHA-256' },
    })
    .setValidityDays(30)
    .generateSerialNumber()
    .selfSign()

// Every object converts to DER (binary) and PEM (base64 text) and back
const der = certificate.toDer()
const pem = certificate.toPem()
console.log('DER:', der.length, 'bytes, starts with', [...der.slice(0, 4)])
console.log('PEM:', pem.split('\n')[0], '...')
console.log(
    'Same certificate from DER and PEM:',
    Certificate.fromDer(der).equals(Certificate.fromPem(pem)),
)

// toString() prints the ASN.1 structure, handy for debugging
console.log('\nASN.1 of the subject public key:')
console.log(certificate.tbsCertificate.subjectPublicKeyInfo.toString())

// Parse bytes you know nothing about into a generic ASN.1 tree
const tree = derToAsn1(der)
console.log('\nTop level:', tree.constructor.name)

// Unknown CMS data: look at the content type first, then parse as that type
const signed = await SignedData.builder()
    .setData(new TextEncoder().encode('data'))
    .addSigner({
        certificate,
        privateKeyInfo: keys.privateKey,
        encryptionAlgorithm: {
            type: 'ECDSA',
            params: { namedCurve: 'P-256', hash: 'SHA-256' },
        },
    })
    .build()
const unknown = ContentInfo.fromDer(signed.toCms().toDer())
console.log('\nCMS content type:', unknown.contentType.friendlyName)
if (unknown.contentType.is('1.2.840.113549.1.7.2')) {
    const parsed = unknown.parseContentAs(SignedData)
    console.log('Signers:', parsed.signerInfos.length)
    console.log('Embedded certificates:', parsed.certificates?.length)
}

// parseAs re-reads a value as another type, e.g. the curve OID in the key's parameters
const curve =
    certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters?.parseAs(
        ObjectIdentifier,
    )
console.log('\nCurve:', curve?.friendlyName, `(${curve})`)
```

## Reading certificates, requests, CRLs and OCSP responses created by OpenSSL

```typescript
import { OIDs } from 'pki-lite/core/OIDs.js'
import { OCSPResponse } from 'pki-lite/ocsp/OCSPResponse.js'
import { CertificateList } from 'pki-lite/x509/CertificateList.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { CertificateRequest } from 'pki-lite/x509/CertificateRequest.js'

console.log('=== Reading OpenSSL output ===\n')

// These were made with, respectively:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...
//   openssl req -new -addext subjectAltName=DNS:a.example,IP:10.0.0.1 ...
//   openssl ca -gencrl ... (with revoked certificates)
//   openssl ocsp -index ... -respout ... (for a revoked certificate)
const certificatePem = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUKBhZ2AVzxLzBZ5xE00YVIYFZDY4wCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEVGVzdDAeFw0yNjExMTExMjQ1NTZaFw0yNjEyMTExMjQ1NTZa
MA8xDTALBgNVBAMMBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT003m7
gsMFGNWU8O8fzRTWI6o44DX4nuAmfi0YWKA8rnnmxQPaTCcDk7bEHVQiylShCOgW
Pj42HyGICe7TwKOro1MwUTAdBgNVHQ4EFgQUyhtApj1b+4SbhqlJAIz9LlElD/sw
HwYDVR0jBBgwFoAUyhtApj1b+4SbhqlJAIz9LlElD/swDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAqeyvJDuaTtqMMICaAUg/3MLYP53DJWZ2hST+
jZ+/Mv0CIDds0y9CS2saR9taicfrW+4AAK5v4AK4gAMNLjB6PVa2
-----END CERTIFICATE-----`

const csrPem = `-----BEGIN CERTIFICATE REQUEST-----
MIICfjCCAWYCAQAwDDEKMAgGA1UEAwwBWDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAIlh38Wr3e7t7tZfLyJm9VU03i5VeFziZfgU87rlKEoncHDRdyJT
Czu9QPEtHHcYiFD52IKmASRRuvXx6cXueeA7/94lANz7m09EM5RHmzpQvsaP6F8C
WXFPff02gqgy5q4fPblxrQ9ZzTLLhdDHc92SKenRoaeKYZ5MqRo+5eJCvq1ONkIn
1LNZHugInBdIGInZz1+QGLyg2hT6SoeOB3RHl7HaA2Mo+NOl8/kV/w6raCDUqRJM
+ZKA+MQzD6w0s6HfJNml01p5WaxtpPnP3Z9phD4859xRr7FiQSC+9pACeAjxPmdC
JHtvjOCskS4SDDwb8YWrr2t6MGI1k69uMY8CAwEAAaAtMCsGCSqGSIb3DQEJDjEe
MBwwGgYDVR0RBBMwEYIJYS5leGFtcGxlhwQKAAABMA0GCSqGSIb3DQEBCwUAA4IB
AQBuaWHZXvm/gPcTDhJfomWHEtgNh2YOnoq4Giyq+g/IOCt2T4OLz+xlo+Jogmlq
bdsRWOnvocUkZyQlAYLWrJg23a1SDhAjzg+OQ4wnbzZaA7IBz+FO3vsQpI2qd26f
rNj65AKv6rGSa9a8exBXvQZsacXyrk2azfI/sEzbTFwxPO2M5+iuPJatWiLXniXR
Djirt4291X61APorU6s3FZd5qK0qa6+Z3qdNCdKXRTP30x3X3sRTjUdZ3LjN1oZG
zOLuOX5Srx/P8Aksf8xcCocNEAj1EjpAi1t1aSUz4gqT+WAf2pknpc9WF5EQYCZ2
9qOWfcqq4ANhe1244mZcpm77
-----END CERTIFICATE REQUEST-----`

const crlPem = `-----BEGIN X509 CRL-----
MIICuDCCAaACAQEwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHVGVzdCBDQRcN
MjYxMTExMTI0NTU4WhcNMjYxMTE4MTI0NTU4WjCCARwwEgIBARcNMjYxMTExMTI0
NTU4WjAgAgECFw0yNjExMTExMjQ1NThaMAwwCgYDVR0VBAMKAQEwIAIBAxcNMjYx
MTExMTI0NTU4WjAMMAoGA1UdFQQDCgECMCACAQQXDTI2MTExMTEyNDU1OFowDDAK
BgNVHRUEAwoBBjAgAgEFFw0yNjExMTExMjQ1NThaMAwwCgYDVR0VBAMKAQgwOgIB
BhcNMjYxMTExMTI0NTU4WjAmMAoGA1UdFQQDCgEBMBgGA1UdGAQRGA8yMDI0MDEw
MTAwMDAwMFowIAIBBxcNMjYxMTExMTI0NTU4WjAMMAoGA1UdFQQDCgEDMCACAQgX
DTI2MTExMTEyNDU1OFowDDAKBgNVHRUEAwoBAKA6MDgwHwYDVR0jBBgwFoAU3NAe
xUQTwAB+w3BNW3VMsMSvoP4wCQYDVR0SBAIwADAKBgNVHRQEAwIBAjANBgkqhkiG
9w0BAQsFAAOCAQEAiTvhbIOtZ8yRnwn3DGkc6FWN1SBJHTNzAET7lskaAGkScULp
MLzhUrZyq+YYo0OfBrh3WI2XeTUmQP8JtNOOFej2GhRzVMxWhevd5O2FyLJ2WFft
RkfvO1YdstatZZEmQkn6BlqumdbS4ngtBS6c18aEGMe9AneBGed7X0fmZmYenq1u
76OAVIeg9pLT7rarfn6auEhCTBMQ7RZtOQk4lABs1AV+dZn2A4UpfysIg5rTHaSP
+eJ0Oo3GpEUYRMJNUDpyFW/3tSqYPElMR6J5ywd9+e8V/G5nUS8sMMMXL142b/GX
uSVzWdoGbZmaguXYibZcWoMHS0sixYZhdPXFtw==
-----END X509 CRL-----`

const ocspBase64 = `MIIE4QoBAKCCBNowggTWBgkrBgEFBQcwAQEEggTHMIIEwzCBi6EUMBIxEDAOBgNV
BAMMB1Rlc3QgQ0EYDzIwMjYxMTExMTI0NTU4WjBiMGAwOjAJBgUrDgMCGgUABBS/
cFLIucD3YMiRI+CZgV6ywDlCJgQU3NAexUQTwAB+w3BNW3VMsMSvoP4CAQGhERgP
MjAyNjExMTExMjQ1NThaGA8yMDI2MTExMTEyNDU1OFowDQYJKoZIhvcNAQELBQAD
ggEBAAArbLxHIxpNFV210Be8CR1U03SxOmk/2gBqWrEv90+4KRc0rlAjxXjZMe+V
aNh+WNjk99uj7mC0l07Q+jD3LaMmD/+xjgpE6KTHqmeeVzQW6DPMQDbAKn+8yFfY
+jYHyO8clz0Y27j8qq8TnAPn6SWAluQnAy+zbRq7sWOqzkq4WE03j03vV9Q3wuIX
24qv3waPP0mwaufCn7NBkGcA2MIw5AHb5T4TuIBulkWZ1EIDRCRPfcHXPSbZhXKg
4bXn2yOIQJCqd0LoAl+38lNGj5bfgav4elOmpJa17E6ozssJFsqa6m1ND9l2C0Xo
fQnuk23kYcyDTcvS9lKKtQJzCmSgggMdMIIDGTCCAxUwggH9oAMCAQICFClgLppy
ennxRqJk/06fVW8A2zxnMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMMB1Rlc3Qg
Q0EwHhcNMjYxMTExMTI0NTU4WhcNMjcxMTExMTI0NTU4WjASMRAwDgYDVQQDDAdU
ZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiWHfxavd7u3u
1l8vImb1VTTeLlV4XOJl+BTzuuUoSidwcNF3IlMLO71A8S0cdxiIUPnYgqYBJFG6
9fHpxe554Dv/3iUA3PubT0QzlEebOlC+xo/oXwJZcU99/TaCqDLmrh89uXGtD1nN
MsuF0Mdz3ZIp6dGhp4phnkypGj7l4kK+rU42QifUs1ke6AicF0gYidnPX5AYvKDa
FPpKh44HdEeXsdoDYyj406Xz+RX/DqtoINSpEkz5koD4xDMPrDSzod8k2aXTWnlZ
rG2k+c/dn2mEPjzn3FGvsWJBIL72kAJ4CPE+Z0Ike2+M4KyRLhIMPBvxhauva3ow
YjWTr24xjwIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjAdBgNVHQ4EFgQU3NAexUQTwAB+w3BNW3VMsMSvoP4wHwYDVR0jBBgwFoAU3NAe
xUQTwAB+w3BNW3VMsMSvoP4wDQYJKoZIhvcNAQELBQADggEBAID7T9q5JYLRMS1W
l51WYvpRd0Pjn4L9j+WWwRfW8Nfiw7nys+hrFlqf9acw3wbTfztQXw9z0tve79Du
QKSAOeWHogZqe791zDYHKKv8vhdUgDK8m2/RkIXUtz+zoiGkbj8R+nRj4t2RI+cw
ltHq53eY5FLHPvTFBGtLCzhW18btQulUoI8rHh68RJ9n1eXnT1tQz4TqINBCb7YB
hq5kBY3inLkVNF5OOdxWp58q9wAtGmx4gHO8xLLcJfoLp1MqyYxDwSbTVzXtTAkv
07wQFwChFMGNAF+LRqSYSq99STgm3CmEljRerUQP7O2dB8AVIJRuCLvaY+raY/QR
JrJhLMw=`

// --- A certificate ---
const certificate = Certificate.fromPem(certificatePem)
console.log('Certificate')
console.log('  Subject:', certificate.tbsCertificate.subject.toHumanString())
console.log(
    '  Signature:',
    certificate.signatureAlgorithm.algorithm.friendlyName,
)
console.log(
    '  Valid:',
    certificate.tbsCertificate.validity.notBefore.toISOString(),
    'to',
    certificate.tbsCertificate.validity.notAfter.toISOString(),
)
console.log(
    '  Self-signed and signature valid:',
    await certificate.isSelfSigned(),
)

// --- A certificate signing request ---
const csr = CertificateRequest.fromPem(csrPem)
console.log('\nCertificate request')
console.log('  Subject:', csr.requestInfo.subject.toHumanString())
console.log(
    '  Public key:',
    csr.requestInfo.publicKey.algorithm.algorithm.friendlyName,
)
for (const attribute of csr.requestInfo.attributes ?? []) {
    console.log('  Attribute:', attribute.type.friendlyName)
}

// --- A CRL ---
const crl = CertificateList.fromPem(crlPem)
const revoked = crl.tbsCertList.revokedCertificates ?? []
console.log('\nCRL from', crl.tbsCertList.issuer.toHumanString())
console.log('  This update:', crl.tbsCertList.thisUpdate.toISOString())
console.log('  Next update:', crl.tbsCertList.nextUpdate?.toISOString())
console.log('  Revoked certificates:', revoked.length)
for (const entry of revoked.slice(0, 3)) {
    const hasReason = entry.crlEntryExtensions?.some(
        (extension) =>
            extension.extnID.value === OIDs.EXTENSION.CRL_REASON_CODE,
    )
    console.log(
        '   ',
        entry.userCertificate,
        'revoked',
        entry.revocationDate.toISOString(),
        hasReason ? '(with a reason code)' : '',
    )
}

// --- An OCSP response ---
const ocsp = OCSPResponse.fromDer(
    Uint8Array.from(atob(ocspBase64.replace(/\s/g, '')), (c) =>
        c.charCodeAt(0),
    ),
)
console.log(
    '\nOCSP response status code:',
    ocsp.responseStatus.value,
    '(0 = successful)',
)
const single = ocsp.getBasicOCSPResponse().tbsResponseData.responses[0]
console.log('  Certificate status:', single.certStatus.status)
console.log('  Revoked at:', single.certStatus.revocationTime?.toISOString())
console.log('  This update:', single.thisUpdate.time.toISOString())
```

## Decrypting what OpenSSL produces by default (RSA PKCS#1 v1.5 and 3DES)

```typescript
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData.js'
import { PFX } from 'pki-lite/pkcs12/PFX.js'

console.log('=== OpenSSL defaults with the extended crypto package ===\n')

const fromBase64 = (text: string) =>
    Uint8Array.from(atob(text.replace(/\s/g, '')), (c) => c.charCodeAt(0))

// `openssl cms -encrypt -aes256 -recip cert.pem` wraps the content key with RSA
// PKCS#1 v1.5, which WebCrypto does not offer.
const cmsBase64 = `MIIBrgYJKoZIhvcNAQcDoIIBnzCCAZsCAQAxggFGMIIBQgIBADAqMBIxEDAOBgNV
BAMMB1Rlc3QgQ0ECFFE2yTfw/ZHSau6Z8W8G1snvhr58MA0GCSqGSIb3DQEBAQUA
BIIBAAoCju/D489GfEcvW//inPaORt6TXYiWiefuLzrrhhnSGn6GtgEHsd/LCZnr
bY3m9XvqvGNR3Ey94Zrl6+eqxCLNG9rSvv3CSwVXioGPpN99yRvK8iwb2IYPSoc6
ETV4ZWQFiKbbf+J4q3Qjlakl1R56iUILnz/WhWa6JLvZe2x7IinyORlAiRbXVgiA
di8TgKMSgU/AJtHKwSA250DHWd1nAgV8Q8tqmnv3Op/1qm1Zs3RWfPGgAse84uDd
xy0kOFlxzx9xTx77fSJxqjzyTFC1zCF+2VLVJ9lSMbfdg9MAcgEP2VUWW+wPDMWI
lADf77QlpSHxn5sjqlHEEtHlMq8wTAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ
xhtaAE3WlTdY04Ulu4DTAYAgdCG01G+Nk2QtWlCEm3f/O2PgBenjtUO3/M3PohI4
t1g=`
const privateKey = PrivateKeyInfo.fromPem(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCJYd/Fq93u7e7W
Xy8iZvVVNN4uVXhc4mX4FPO65ShKJ3Bw0XciUws7vUDxLRx3GIhQ+diCpgEkUbr1
8enF7nngO//eJQDc+5tPRDOUR5s6UL7Gj+hfAllxT339NoKoMuauHz25ca0PWc0y
y4XQx3Pdkinp0aGnimGeTKkaPuXiQr6tTjZCJ9SzWR7oCJwXSBiJ2c9fkBi8oNoU
+kqHjgd0R5ex2gNjKPjTpfP5Ff8Oq2gg1KkSTPmSgPjEMw+sNLOh3yTZpdNaeVms
baT5z92faYQ+POfcUa+xYkEgvvaQAngI8T5nQiR7b4zgrJEuEgw8G/GFq69rejBi
NZOvbjGPAgMBAAECggEACcwsRcV6h+TPFi8RRk5PwRpf8q+kwaxht54Nkxlu/07Y
aCtVaDds7dSS55WfLz0q0j+R5HYLTyLxsZg64vidbNOf7UtNSEqR/8auOQJxpxMw
GoAT2IbAiIyx6wIysjp4ahg58i+Rty5hLHYISTnti502FldIGec2tq/ilXJr5EVh
4jOWXXQ8PVc33agBDf2Br06/S2urQiAxCnx9ewjndB/H+w+PXrreMfKm/ZbUwU/1
TSnWvB1yT+z1yJsertlM0me3LnpHIIrFLX8FvfOPKTa+Gcs6kq7Kyw7s8qSkPGKg
Z3yFv4Qzolh75PiQQYGek4JMtIPw09E95nrYoDQF1QKBgQC9ALwkpemwN/Z3oZFl
5b+DbO+VXqz7whsowURKr+9TEi0hB0vIM4CvNUJ6DaM30MRydVm6Z0a+Y55Z381L
IR4OunN7uOG8ILxKNyEUeW2fU3kcV5AyiFYVWdm0FpiIjzUkvn9yrtx7hwjOh8Wz
hlWfyFnobCgNpYjwBDIJ5kqN0wKBgQC6FMchjl7b2UlyTrdUib38V8gK6GDTZKXR
KvLvqiMjJqcUEwYWZjnE0ozL9zKjcut/5F0Keh7PXD2a/+rJVnGA1XZKfzvBQpAG
YPCfv4LtdHefjGitqihFiLnRpfJ069vhDjK9Ow+YHAFBFXXUS1mSctC6+d/xNRUK
9eUiJwVr1QKBgBfg9+RJcfTpnSIQL6aIGGIqaTqd84z7QSMtB8vH3pzINxttKI3q
s99vAy8Yef6bSbaMTQHX+oAjZeZE+FL9pCaIN/7xpNN371IRFQTZMphmm26RQY6g
2v9nkrHGCQ93yGcUClYa8ZBJxzsQvFGqLzc4wOM0hvryZxKr9QZ7KgAxAoGAXRwy
fAb6TjXOu4TJ1WJLD255KYQXlw9grWY5Q1U12cvohHH0dNbYBzV3wEPEMec6Ebea
Grj6m7XDGcD+oZpAlz+4vhQmOVDuMlLldHnmsJy7krk2U9e16P0+RbostPakAlwR
ZYCdD/bLZd6wI/dELbSH31dTCCYQjnh2G/28h7UCgYAjWats6wG1V2yCpF35+RXg
C4FDK2izwoQafdpsvWFx00ce4WEeiJTBjUZ/Iec5ZbQ2jW3f2Z0BKBd3lovJkagi
GndtOxfMvOylDc9/S63Q2Mnwcu6RVgMtg0Mb1BD3ReBMmO9zCsoYNo5+m48otUA6
y78dk/1k3Ju2FAiCapL/vw==
-----END PRIVATE KEY-----`)

// `openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES`: password "pw"
const legacyPfxBase64 = `MIIJcQIBAzCCCS8GCSqGSIb3DQEHAaCCCSAEggkcMIIJGDCCA88GCSqGSIb3DQEH
BqCCA8AwggO8AgEAMIIDtQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIVMzI
ICJCkB8CAggAgIIDiDkES39f5NRv7c3MGSwfbmH8N5qK3cRQLMVDgvF0iYrVKfoD
PKNjRiROUktWXLPSWkAuV4ttyle83LvyCRzZEWI3N8ggBQCAhl5yh/0VnxucI7mR
GXBTv8/KUSgAZKfRQ0XD7v7M2KWsXCrs9EdQBRrRmCcHma5l4R5CrevxSLAtkvUU
JBxbcSAJUTsStSLxTjJLktLPm/gsUdZLTLnTqOIHl7vpLLeou959OjKUAqRRYrcp
QZ3HiHBJnVUqpARYkv9LtmlFbmE8Oa4TIvCZ8V/6dzKnhhQDGNby1Q74GGech7tE
AJBnMQB8aI4AIK4QS203TGkJn1mGCWxbSuubnENQe64/diu+Gi9RoFKM+4j39n3f
zpZ8KrYLfDEmUdJ7ooP4ZEk4dDTFfql6epWGgW6TFj4+oCExHysUzmlUDaQb9OeE
2TeXDlUO50z3PPjBdBLp2WST6gGsDKl86U8Vd+NtZ6CrbcETXYHp/FtlbIk08N9N
MfETmhs1H8kOqrly0/NA8+Dwg6QOb9WccHvJsxF3acpQ5nkj2qS4Pe8TIQ2ch4Mk
kO1e6j30rME0BSmN5UaeVmah1OW1ti3jNOQ097fy+QsYmZ7Kg7qaSqIs8EwrTtXI
CHUMGI2Oozlk1qfa4abZOGYdtvFYH3+4ymHh1kF5+MVrDeQ2xHdzTKu4r5DW/G+x
+Fhqlk6dYP4QPhFB4+7LOIo8OuC8o4RpuLxqJb/dML1UIJl75psvvfARLAxvoOow
jEQ+1IeX/1XQoqzu19awSdSwu90eMt+IUCS/cFIuyIXZZ4gMzfyVF3qzKQZ7GQvp
ZzDcIWtlksOQZu31uN9YzjOhYgFlbyYBXb1EV6hddZzP/Jui53/LFMynzzmADMhg
TNeInsNXSDBwSrddZZSc7Zl0PboenBHihzvMrVluYKft8FOd+wJUh/Q5Ev36+AiC
UCoQpfaAd6IfiGWWWCox+Coy2uAySdX1wQxOytqwZ/mzk2AFBu49OpJfyhMtKbPM
PTqrxqakjyR5zyp9rScRSCjFq59SC8yAwi4BHR/1AOLsjw/gYSl4JiEVTTgZ2tBh
yYIIQSDPxLOcQ1AXEgcJ2QyjULA5ZNlCvuNY6oi3FzjriYZ2bx5Jujg78Juxy/oF
0XHOB1eHKFmgIs9oiOm/O+l/GZBkKc0kOhW1XOhGZZx8SO88BG/+XHCb2qfTnH45
CQIL9rQwggVBBgkqhkiG9w0BBwGgggUyBIIFLjCCBSowggUmBgsqhkiG9w0BDAoB
AqCCBO4wggTqMBwGCiqGSIb3DQEMAQMwDgQIvOQ70WmoD0YCAggABIIEyMAKvhVE
qPGcdWyUaXHSRzA1JMuMhpyWNKCsRq0aJ14aRa5uy0lYKyxT80OBUebwBA48rFDw
4mthsumi5xZRAeNPByMI2NrNz/hTNZYlK4U4GCzM6DGd1w4xguxzABZv8Xa6PoPg
QPbNFGExmEXAjAhjdBxys/mRs8wHYW/6aN1QL87CLhQI+I8NwPFo6pXr4Toe5yOB
iI1skpJmJl1ittGgpMKkYdjpsA42ptpzxhsKTRcC+4h8/FWHeT39A/iooAbeZdap
fBrtUqbzynYpT9V//8KvSxKbBGKOH3qi3ot7Fz48kxhp2BXgzIhI/I2+gJHfUdCB
YERycMVpFv6nRzRShgjwkM10tIF4/CRsMM/C5AcuynN+hWraJUmzmGgfA/cBNsTC
vyRGnfTW0BpGWqToREgy6tUFtyFuQTqPXSvZ+C/UPVsmQodoANA3w253zxk6Nen/
T444hsWIyvI3PhQbnIyh3CCTyXtTwM9SOTCx8BL8qQuPVmWEUAXnEGHvo1lLo0CJ
dOUT9yIvxCSM6E2GCdFr2lgZufCtqvtBHnVWs3+bFyaH2noO0UB4JgFUgM/KDW+Z
uTxGtNoBneibhTIiWJ+3qaWqWemjI0+DD84lRbJRzaKcNMYz65sfRBkMHxoTllPj
rZDhfYIZUovxwlR+2wkFIiT4fPD9f8xQiBi8PLfyrJGx1RDiuSgn9GmrEbMLpY13
BqtoXIs10PyCBYI315+yMmg0ZER/H1o7bWePpOBLk0NtZcx+fsbEGkYYblB+B2nr
5W1xgdbShCi4XB5+T8TRo68MeOLydvjQQ5icp6MUogY4QstAUfjcjSr3HjSlVrT4
2Kv5r9AgOblOkAtzLE2os0h8kbdErXUX9KeQaWeyOqE3VnZZwXkZQCNDyW14WzQ6
nVVjMGiuiSKaYOz2k8kNx6jVJ7aRpXjAkkyWY4YHnKmbqJysWSIC3jPIVfcR98py
hDVr1tY4VLEsFqC7wQqoWdJu9CvVkwbOeNIFQSNvIL9Hx351J4x5BvcPkbigQGbm
KxQAQxwpMcl9wgheYjd+i3Nk1exwDRB7FLQ8sF70nFsU7gtiqoPIzlpDmhviV2uY
pA8xPQHX9gsAxkdHSVy0Lj6R9+BIoy76Ng0iiSM+jSowAbE3oyBaCmsMOiUG9lKY
nZBqMyJtrEhMtzl9s9WR/C8it8+zk0qGbTXNYZXd2lx9q/fNB+nOQU7pbeKNodhN
P5wSgdr3Cd91s0AGQnvzz5BzvPMe0tieV5LnxktAJEpUgsUZfE+an3u3pLzf5j14
/sZMDlOfVba0N+tOQk4o+c7YRw348EmUL3SQH5IkurBFWWgXxk21WHXNvn0zOnF8
QQfYnN+gVwpWFwHSpYVNNLOyf8TtCUWmrGLw7kr7gw8xx0Fxt6GS+8jtfQ0mScQX
qcQdBSjLgOXv6Qwi2Ir5awO5C0jsqi6dtKd3N3XksCMoEr2SAt4HH+7+v51D0Rcz
V2icWwZkeGnnhhorwTm5yGto167IhDtrUT3iq6NeS8ATEE04fjaEPT6NCBcx1Rqi
HuJDlfxMmlLA1aJf5qI2Fs8swmZMg+DOry/oCmj5vMQbyET4E+62nqa35i+OvInF
5+0kPYe/NbuolTOpb16racbv2jElMCMGCSqGSIb3DQEJFTEWBBTS04hqyM2MZZ9u
aBYrElTXQMWE7DA5MCEwCQYFKw4DAhoFAAQUwbWkl1F8n+KmvZO2+fDgsZozFpEE
EGLpy1PI5e2D528FkHbE+cECAggA`

const envelopedData = EnvelopedData.fromCms(fromBase64(cmsBase64))

// With only the default provider, RSA PKCS#1 v1.5 key transport is not available
try {
    await envelopedData.decrypt(privateKey)
    console.log('Default provider: decrypted (unexpected)')
} catch {
    console.log('Default provider: cannot decrypt (no RSA PKCS#1 v1.5)')
}

// Importing the extended package installs a provider that adds RSA PKCS#1 v1.5, 3DES, MD5
// and more. Do this once at start-up; it applies to all of pki-lite.
await import('pki-lite-crypto-extended')

const plaintext = await envelopedData.decrypt(privateKey)
console.log(
    'Extended provider: decrypted ->',
    JSON.stringify(new TextDecoder().decode(plaintext).trimEnd()), // OpenSSL adds a CRLF
)

// The same provider reads the legacy 3DES-encrypted PKCS#12 files many tools still write
const pfx = PFX.fromDer(fromBase64(legacyPfxBase64))
const { privateKeys, certificates } = await pfx.extractItems('pw')
console.log(
    `3DES PKCS#12: ${privateKeys.length} private key, ${certificates.length} certificate`,
)
console.log(
    '  Certificate:',
    certificates[0].tbsCertificate.subject.toHumanString(),
)
```

## Certificate policies: requiring, mapping and constraining policies along a chain

```typescript
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Certificate Policies Example ===\n')

// Policy OIDs: what the root's domain calls "high assurance", and what the
// intermediate CA's own domain calls it
const ROOT_HIGH_ASSURANCE = '1.3.6.1.4.1.99999.1.1'
const SUBCA_HIGH_ASSURANCE = '1.3.6.1.4.1.99999.2.1'
const LOW_ASSURANCE = '1.3.6.1.4.1.99999.1.9'

// The CAs sign with RSA (the builder's default signature algorithm)
const [rootKeys, caKeys, leafKeys] = await Promise.all([
    KeyGen.generateRsaPair({ keySize: 2048 }),
    KeyGen.generateRsaPair({ keySize: 2048 }),
    KeyGen.generateEcPair({ namedCurve: 'P-256' }),
])

const root = await Certificate.builder()
    .setSubject('CN=Policy Root')
    .setPublicKey(rootKeys.publicKey)
    .setPrivateKey(rootKeys.privateKey)
    .setValidityDays(3650)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .selfSign()

// The intermediate CA asserts the root's policy, says its own domain's OID means the
// same (a policy mapping), and requires every certificate below it to carry an
// acceptable policy (requireExplicitPolicy: 0)
const intermediate = await Certificate.builder()
    .setSubject('CN=Policy Sub CA')
    .setIssuer(root)
    .setPublicKey(caKeys.publicKey)
    .setIssuerPrivateKey(rootKeys.privateKey)
    .setValidityDays(1825)
    .generateSerialNumber()
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .addCertificatePolicies(ROOT_HIGH_ASSURANCE)
    .addPolicyMappings({
        issuerDomainPolicy: ROOT_HIGH_ASSURANCE,
        subjectDomainPolicy: SUBCA_HIGH_ASSURANCE,
    })
    .addPolicyConstraints({ requireExplicitPolicy: 0 })
    .sign()

async function leaf(...policies: string[]) {
    const builder = Certificate.builder()
        .setSubject('CN=server.example.com')
        .setIssuer(intermediate)
        .setPublicKey(leafKeys.publicKey)
        .setIssuerPrivateKey(caKeys.privateKey)
        .setValidityDays(90)
        .generateSerialNumber()
        .addBasicConstraints(false)
    if (policies.length > 0) builder.addCertificatePolicies(...policies)
    return builder.sign()
}

const validator = new CertificateValidator()
const validate = (certificate: Certificate, options: object = {}) =>
    validator.validate(certificate, {
        validateChain: true,
        trustAnchors: [{ certificate: root }],
        otherCertificates: [intermediate],
        ...options,
    })

const cases: [string, Certificate, object][] = [
    // the leaf uses the sub CA's OID, which the mapping ties to the root's policy
    ['mapped high-assurance leaf', await leaf(SUBCA_HIGH_ASSURANCE), {}],
    // the CA's policy constraints demand a policy, and this leaf has none
    ['leaf without policies', await leaf(), {}],
    // a policy the CA never asserted is not valid for the path
    ['low-assurance leaf', await leaf(LOW_ASSURANCE), {}],
    // the relying party only accepts the root's high-assurance policy
    [
        'mapped leaf, only high assurance accepted',
        await leaf(SUBCA_HIGH_ASSURANCE),
        { initialPolicySet: [ROOT_HIGH_ASSURANCE] },
    ],
    // ...but refuses policy mapping altogether
    [
        'mapped leaf, mappings not allowed',
        await leaf(SUBCA_HIGH_ASSURANCE),
        { initialPolicyMappingInhibit: true },
    ],
]

for (const [label, certificate, options] of cases) {
    const result = await validate(certificate, options)
    console.log(`${label.padEnd(42)} valid: ${result.isValid}`)
    if (result.isValid) {
        console.log(`    valid policies: ${result.policyResult?.validPolicies}`)
    } else {
        console.log(`    ${result.messages.join('; ')}`)
    }
}
```
