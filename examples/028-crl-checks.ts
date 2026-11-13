// Checking certificates against a CRL: verify, isCurrent, isRevoked and full revocation checking

import { CertificateList } from 'pki-lite/x509/CertificateList.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'

// A CA, and two certificates it issued
const caKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const ca = await Certificate.builder()
    .setSubject('CN=Example CA, O=Example Org, C=US')
    .setPublicKey(caKeys.publicKey)
    .setPrivateKey(caKeys.privateKey)
    .setValidityDays(3650)
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .selfSign()

const issue = async (commonName: string, serial: number) => {
    const keys = await KeyGen.generateRsaPair({ keySize: 2048 })
    return Certificate.builder()
        .setSubject(`CN=${commonName}, O=Example Org, C=US`)
        .setPublicKey(keys.publicKey)
        .setIssuer(ca)
        .setIssuerPrivateKey(caKeys.privateKey)
        .setSerialNumber(serial)
        .setValidityDays(365)
        .sign()
}
const alice = await issue('Alice', 1001)
const bob = await issue('Bob', 1002)

// The CA revokes Bob's certificate
const crl = await CertificateList.builder()
    .setIssuerFromCertificate(ca)
    .setPrivateKey(caKeys.privateKey)
    .setNextUpdate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000))
    .revokeCertificate(bob)
    .build()

// A relying party receives the CRL as DER or PEM
const received = CertificateList.fromPem(crl.toPem())

// 1. Is the CRL genuine (signed by the CA's key, which may sign CRLs) and current?
console.log('Signed by the CA:', await received.verify(ca))
console.log('Signed by Alice:', await received.verify(alice))
console.log('Current:', received.isCurrent())

// 2. Does it list a certificate?
console.log('Alice revoked:', received.isRevoked(alice))
console.log('Bob revoked:', received.isRevoked(bob))
console.log('Bob revoked on:', received.getRevokedEntry(bob)?.revocationDate)

// 3. Or let the validator do all of it as RFC 5280 6.3 describes, for every certificate in
// the path: the CRL must be from the right issuer, current, in scope and properly signed,
// and a certificate no usable CRL covers is CRL_UNAVAILABLE rather than VALID
const validator = new CertificateValidator()
for (const certificate of [alice, bob]) {
    const result = await validator.validate(
        certificate,
        {
            validateChain: true,
            trustAnchors: [{ certificate: ca }],
            checkCRL: true,
        },
        { crls: [received] },
    )
    console.log(`${certificate.getCommonName()}: ${result.status}`)
}

const noCrl = await validator.validate(
    alice,
    {
        validateChain: true,
        trustAnchors: [{ certificate: ca }],
        checkCRL: true,
    },
    { crls: [] },
)
console.log('Alice with no CRL:', noCrl.status)
