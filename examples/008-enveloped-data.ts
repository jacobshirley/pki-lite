// Create a CMS EnvelopedData structure with a signer

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
