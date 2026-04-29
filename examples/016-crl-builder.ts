// Building a Certificate Revocation List (CRL) using the CertificateList builder

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
