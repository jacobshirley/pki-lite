// Protecting a private key with a password (PKCS#8 EncryptedPrivateKeyInfo)

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { EncryptedPrivateKeyInfo } from 'pki-lite/keys/EncryptedPrivateKeyInfo.js'

console.log('=== Encrypted Private Key Example ===\n')

const { privateKey } = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
console.log('Plain PKCS#8 PEM header:', privateKey.toPem().split('\n')[0])

// Encrypt with a password using PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC)
const password = 'correct horse battery staple'
const encrypted = await EncryptedPrivateKeyInfo.create(privateKey, password, {
    iterations: 100_000, // more iterations make password guessing slower
})

// The PEM can be stored or shared: `openssl pkey -in key.pem` reads it
const pem = encrypted.toPem()
console.log('\nEncrypted PEM:')
console.log(pem)

// Load it back and decrypt
const loaded = EncryptedPrivateKeyInfo.fromPem(pem)
const decrypted = await loaded.decrypt(password)
console.log(
    '\nDecrypted key matches the original:',
    decrypted.equals(privateKey),
)

// A wrong password fails instead of returning garbage
try {
    await loaded.decrypt('wrong password')
    console.log('Wrong password was accepted (unexpected)')
} catch {
    console.log('Wrong password rejected')
}
