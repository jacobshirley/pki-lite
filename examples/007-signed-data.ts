// Create a CMS SignedData structure with a signer

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
