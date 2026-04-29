// Create a CMS EnvelopedData structure with a recipient

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData'
import { Certificate } from 'pki-lite/x509/Certificate'

console.log('=== Enveloped Data Example ===\n')

// Generate a key pair and create a certificate for the recipient
console.log('Generating RSA key pair for recipient...')
const keyPair = await KeyGen.generateRsaPair({ keySize: 2048 })

console.log('Creating recipient certificate...')
const certificate = await Certificate.builder()
    .setSubject('CN=Recipient, O=Example Org')
    .setPublicKey(keyPair.publicKey)
    .setPrivateKey(keyPair.privateKey)
    .setValidityDays(365)
    .generateSerialNumber()
    .selfSign()

console.log('✓ Certificate created\n')

// Create enveloped data (encrypted message)
console.log('Creating enveloped data...')
const plaintext = 'Hello, World! This is a secret message.'
const envelopedData = await EnvelopedData.builder()
    .setData(new TextEncoder().encode(plaintext))
    .addRecipient({ certificate })
    .build()

console.log('✓ Enveloped data created')
console.log('\nEnveloped Data (CMS):')
console.log(envelopedData.toCms().toString())

// Decrypt the enveloped data
console.log('\nDecrypting...')
const decrypted = await envelopedData.decrypt(keyPair.privateKey)
console.log('✓ Decrypted successfully')
console.log('Decrypted text:', new TextDecoder().decode(decrypted))
