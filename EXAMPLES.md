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

import { AlgorithmIdentifier } from 'pki-lite/algorithms/AlgorithmIdentifier'

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
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo'
import { SignedData } from 'pki-lite/pkcs7/SignedData'
import { Certificate } from 'pki-lite/x509/Certificate'

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
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData'
import { Certificate } from 'pki-lite/x509/Certificate'

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
