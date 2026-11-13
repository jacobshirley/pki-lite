// Validating a TLS server certificate: host names, extended key usage, path length and the RFC 5280 profile

import { Certificate } from 'pki-lite/x509/Certificate.js'
import { GeneralName } from 'pki-lite/x509/GeneralName.js'
import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { CertificateValidator } from 'pki-lite/core/CertificateValidator.js'

// A root CA, an intermediate CA and a server certificate, with the key identifiers and
// critical basicConstraints that the RFC 5280 profile asks of conforming CAs
const rootKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const root = await Certificate.builder()
    .setSubject('CN=Example Root CA')
    .setPublicKey(rootKeys.publicKey)
    .setPrivateKey(rootKeys.privateKey)
    .setSerialNumber(1)
    .setValidityDays(3650)
    .addBasicConstraints(true)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .addSubjectKeyIdentifier(new Uint8Array([1]))
    .selfSign()

const caKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const intermediate = await Certificate.builder()
    .setSubject('CN=Example Issuing CA')
    .setPublicKey(caKeys.publicKey)
    .setIssuer(root)
    .setIssuerPrivateKey(rootKeys.privateKey)
    .setSerialNumber(2)
    .setValidityDays(1825)
    .addBasicConstraints(true, 0)
    .addKeyUsage({ keyCertSign: true, cRLSign: true })
    .addSubjectKeyIdentifier(new Uint8Array([2]))
    .addAuthorityKeyIdentifier(new Uint8Array([1]))
    .sign()

const serverKeys = await KeyGen.generateRsaPair({ keySize: 2048 })
const server = await Certificate.builder()
    .setSubject('CN=www.example.com')
    .setPublicKey(serverKeys.publicKey)
    .setIssuer(intermediate)
    .setIssuerPrivateKey(caKeys.privateKey)
    .setSerialNumber(3)
    .setValidityDays(90)
    .addKeyUsage({ digitalSignature: true })
    .addExtendedKeyUsage({ serverAuth: true })
    .addAuthorityKeyIdentifier(new Uint8Array([2]))
    .addSubjectAltName(
        'www.example.com',
        '*.api.example.com',
        GeneralName.iPAddress.fromString('192.0.2.10'),
    )
    .sign()

// 1. Host names (RFC 9525): DNS names and IP addresses from the subjectAltName only
for (const host of [
    'www.example.com',
    'v1.api.example.com', // the wildcard covers one label
    'a.b.api.example.com',
    '192.0.2.10',
    'example.com',
]) {
    console.log(`valid for ${host}:`, server.matchesHostname(host))
}

// 2. Extended key usage
console.log('serverAuth allowed:', server.allowsExtendedKeyUsage('serverAuth'))
console.log('clientAuth allowed:', server.allowsExtendedKeyUsage('clientAuth'))

// 3. All of it while validating the path, as a TLS client would
const validator = new CertificateValidator()
const options = {
    validateChain: true,
    trustAnchors: [{ certificate: root }],
    otherCertificates: [intermediate],
    requiredExtendedKeyUsages: ['serverAuth'],
    maxPathLength: 1, // at most one intermediate
    strictProfile: true, // also hold the certificates to the RFC 5280 profile
}
for (const hostname of ['www.example.com', 'mail.example.com']) {
    const result = await validator.validate(server, { ...options, hostname })
    console.log(`${hostname}: ${result.status}`)
}
const asClient = await validator.validate(server, {
    ...options,
    hostname: 'www.example.com',
    requiredExtendedKeyUsages: ['clientAuth'],
})
console.log('as a client certificate:', asClient.status)
