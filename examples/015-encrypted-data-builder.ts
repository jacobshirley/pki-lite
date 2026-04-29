// Building encrypted data using the EncryptedData builder

import { EncryptedData } from 'pki-lite/pkcs7/EncryptedData.js'
import { OIDs } from 'pki-lite/core/OIDs.js'
import { getCryptoProvider } from 'pki-lite/core/crypto/provider.js'

console.log('=== EncryptedData Builder Examples ===\n')

const secretMessage = new TextEncoder().encode(
    'This is a secret message that needs to be encrypted!',
)
const password = 'mySecurePassword123'

// Example 1: Basic encryption with default settings (PBES2)
console.log('=== Example 1: Basic Encryption with Default Settings ===')
const basicEncrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .build()

console.log('✓ Data encrypted with default PBES2 algorithm')
console.log('  Version:', basicEncrypted.version)
console.log(
    '  Content type:',
    basicEncrypted.encryptedContentInfo.contentType.value,
)
console.log(
    '  Encrypted size:',
    basicEncrypted.encryptedContentInfo.encryptedContent?.bytes.length,
    'bytes',
)
console.log(
    '  Algorithm:',
    basicEncrypted.encryptedContentInfo.contentEncryptionAlgorithm.friendlyName,
)

// Decrypt to verify
const provider = getCryptoProvider()
const algorithm1 = provider.toSymmetricEncryptionAlgorithmParams(
    basicEncrypted.encryptedContentInfo.contentEncryptionAlgorithm,
)
const decrypted1 = await provider.decryptSymmetric(
    basicEncrypted.encryptedContentInfo.encryptedContent!.bytes,
    password as any, // Type definitions need updating to accept string
    algorithm1,
)
console.log('✓ Decrypted successfully:', new TextDecoder().decode(decrypted1))
console.log()

// Example 2: Encryption with custom PBKDF2 iterations
console.log('=== Example 2: Custom Iterations for PBKDF2 ===')
const customIterations = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .setAlgorithm({
        type: 'PBES2',
        params: {
            derivationAlgorithm: {
                type: 'PBKDF2',
                params: {
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    iterationCount: 100000, // Higher security
                    hash: 'SHA-256',
                },
            },
            encryptionAlgorithm: {
                type: 'AES_256_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            },
        },
    })
    .build()

console.log('✓ Data encrypted with 100,000 PBKDF2 iterations')
console.log(
    '  Algorithm:',
    customIterations.encryptedContentInfo.contentEncryptionAlgorithm
        .friendlyName,
)
console.log()

// Example 3: Encryption with SHA-512 hash
console.log('=== Example 3: Using SHA-512 for Key Derivation ===')
const sha512Encrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .setAlgorithm({
        type: 'PBES2',
        params: {
            derivationAlgorithm: {
                type: 'PBKDF2',
                params: {
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    iterationCount: 50000,
                    hash: 'SHA-512', // More secure hash
                },
            },
            encryptionAlgorithm: {
                type: 'AES_256_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            },
        },
    })
    .build()

console.log('✓ Data encrypted using SHA-512 for key derivation')
console.log(
    '  Algorithm:',
    sha512Encrypted.encryptedContentInfo.contentEncryptionAlgorithm
        .friendlyName,
)
console.log()

// Example 4: Encryption with AES-128 (smaller key size)
console.log('=== Example 4: Using AES-128-CBC ===')
const aes128Encrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(secretMessage)
    .setPassword(password)
    .setAlgorithm({
        type: 'PBES2',
        params: {
            derivationAlgorithm: {
                type: 'PBKDF2',
                params: {
                    salt: crypto.getRandomValues(new Uint8Array(16)),
                    iterationCount: 10000,
                    hash: 'SHA-256',
                },
            },
            encryptionAlgorithm: {
                type: 'AES_128_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            },
        },
    })
    .build()

console.log('✓ Data encrypted with AES-128-CBC')
console.log()

// Example 5: Using EncryptedData.create() shorthand
console.log('=== Example 5: Using EncryptedData.create() Shorthand ===')
const shorthand = await EncryptedData.create({
    contentType: 'DATA',
    data: secretMessage,
    password,
    iterations: 50000,
})

console.log('✓ Data encrypted using shorthand method')
console.log('  Encrypted size:', shorthand.toDer().length, 'bytes')
console.log()

// Example 6: Export to DER and convert to CMS
console.log('=== Example 6: Export and Convert to CMS ===')
const der = basicEncrypted.toDer()
console.log('✓ Encrypted data exported to DER')
console.log('  DER size:', der.length, 'bytes')

// Convert to CMS ContentInfo
const cms = basicEncrypted.asCms()
console.log('✓ Converted to CMS ContentInfo')
console.log('  Content type:', cms.contentType.value)
console.log('  CMS size:', cms.toDer().length, 'bytes')
