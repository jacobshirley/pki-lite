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
    'password', // Can also be a Uint8Array
)

const decrypted = await algorithm.decrypt(
    encrypted,
    'password', // Can also be a Uint8Array
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

## Create a CMS EnvelopedData structure with a signer

```typescript
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo'
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData'
import { Certificate } from 'pki-lite/x509/Certificate'

const certPem = `-----BEGIN CERTIFICATE-----{your certificate here}-----END CERTIFICATE-----`
const privateKeyPem = `-----BEGIN PRIVATE KEY-----{your private key here}-----END PRIVATE KEY-----`

const privateKey = PrivateKeyInfo.fromPem(privateKeyPem)
const certificate = Certificate.fromPem(certPem)

const envelopedData = await EnvelopedData.builder()
    .setData(new TextEncoder().encode('Hello, World!'))
    .addRecipient({ certificate })
    .build()

console.log(envelopedData.toCms())

const decrypted = await envelopedData.decrypt(privateKey)
console.log('Decrypted:', new TextDecoder().decode(decrypted))
```
