// Creating a self-signed certificate

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
