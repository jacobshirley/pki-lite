// Authenticated encryption with CMS AuthEnvelopedData (AES-GCM)

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { asn1js } from 'pki-lite/core/PkiBase.js'
import { AuthEnvelopedData } from 'pki-lite/pkcs7/AuthEnvelopedData.js'
import { Attribute } from 'pki-lite/x509/Attribute.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== AuthEnvelopedData Example ===\n')

// The recipient: an RSA key pair and a certificate
const keyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const certificate = await Certificate.builder()
    .setSubject('CN=Recipient, O=Example Org')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .selfSign()

// Encrypt. Unlike EnvelopedData, the content is encrypted with AES-GCM, so any change
// to it is detected on decryption. The default is AES-256-GCM with a 16-byte tag.
const message = 'Confidential and tamper-evident'
const authEnvelopedData = await AuthEnvelopedData.builder()
    .setData(message)
    .addRecipient({ certificate })
    .build()

const cipher = authEnvelopedData.authEncryptedContentInfo
console.log('Cipher:', cipher.contentEncryptionAlgorithm.algorithm.friendlyName)
console.log('Ciphertext bytes:', cipher.encryptedContent?.bytes.length)
console.log('Authentication tag (mac) bytes:', authEnvelopedData.mac.length)

// Send it as DER (this is what `openssl cms -decrypt -inform DER` reads) ...
const der = authEnvelopedData.toCms().toDer()
console.log('CMS size:', der.length, 'bytes')

// ... and the recipient parses and decrypts it
const received = AuthEnvelopedData.fromCms(der)
const plaintext = await received.decrypt(keyPair.privateKey)
console.log('Decrypted:', new TextDecoder().decode(plaintext))

// Tampering is detected: flipping one bit of the ciphertext or the tag makes
// decryption fail instead of returning altered data.
const tampered = AuthEnvelopedData.fromCms(der)
tampered.mac[0] ^= 1
try {
    await tampered.decrypt(keyPair.privateKey)
    console.log('Tampering was NOT detected (unexpected)')
} catch {
    console.log('Tampered message rejected: authentication failed')
}

// Authenticated attributes travel with the message and are covered by the tag, so they
// cannot be altered either. (A content-type attribute is added automatically.)
const withAttributes = await AuthEnvelopedData.builder()
    .setData('Message with authenticated metadata')
    .addAuthenticatedAttribute(
        new Attribute({
            type: '1.2.3.4.5', // an application-specific OID
            values: [new asn1js.Integer({ value: 42 })],
        }),
    )
    .addRecipient({ certificate })
    .build()

console.log(
    '\nAuthenticated attributes:',
    [...(withAttributes.authAttrs ?? [])].map((attribute) =>
        attribute.type.toString(),
    ),
)
console.log(
    'Decrypted:',
    new TextDecoder().decode(await withAttributes.decrypt(keyPair.privateKey)),
)

// Choose the cipher and tag length yourself: AES-128-GCM with a 12-byte tag
const compact = await AuthEnvelopedData.builder()
    .setData('Shorter tag, smaller key')
    .setContentEncryptionAlgorithm({
        type: 'AES_128_GCM',
        params: {
            nonce: crypto.getRandomValues(new Uint8Array(12)),
            icvLen: 12, // tag length in bytes (12 to 16)
        },
    })
    .addRecipient({ certificate })
    .build()
console.log(
    '\nAES-128-GCM, tag bytes:',
    compact.mac.length,
    '->',
    new TextDecoder().decode(await compact.decrypt(keyPair.privateKey)),
)
