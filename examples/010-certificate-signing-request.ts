// Creating a Certificate Signing Request (CSR) / PKCS#10

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
