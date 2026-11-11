// Creating and verifying a detached CMS signature

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
