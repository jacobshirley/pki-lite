/**
 * Example usage of pki-lite-crypto-extended
 *
 * This file demonstrates how to use the extended cryptographic capabilities
 * provided by this package.
 */

import 'pki-lite-crypto-extended' // Automatically sets up extended provider
import { getCryptoProvider } from 'pki-lite/core/crypto/crypto.js'

async function demonstrateUsage() {
    const provider = getCryptoProvider()

    // Example 1: MD5 Hashing
    console.log('=== MD5 Hashing ===')
    const data = new TextEncoder().encode('Hello, World!')
    const md5Hash = await provider.digest(data, 'MD5')
    console.log(
        'MD5:',
        Array.from(md5Hash)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(''),
    )

    // Example 2: AES ECB Encryption
    console.log('\n=== AES ECB Encryption ===')
    const key128 = new Uint8Array(16).fill(0x01)
    const plaintext = new TextEncoder().encode('Secret message!!')

    const ecbCiphertext = await provider.encryptSymmetric(plaintext, key128, {
        type: 'AES_128_ECB',
        params: {},
    })

    const ecbDecrypted = await provider.decryptSymmetric(
        ecbCiphertext,
        key128,
        {
            type: 'AES_128_ECB',
            params: {},
        },
    )

    console.log('Original:', new TextDecoder().decode(plaintext))
    console.log('Decrypted:', new TextDecoder().decode(ecbDecrypted))
    console.log(
        'Match:',
        new TextDecoder().decode(plaintext) ===
            new TextDecoder().decode(ecbDecrypted),
    )

    // Example 3: AES CBC Without Padding
    console.log('\n=== AES CBC (No Padding) ===')
    const key256 = new Uint8Array(32).fill(0x01)
    const iv = new Uint8Array(16).fill(0x02)
    const blockAlignedData = new Uint8Array(16).fill(0x03) // Must be multiple of 16 bytes

    const cbcCiphertext = await provider.encryptSymmetric(
        blockAlignedData,
        key256,
        {
            type: 'AES_256_CBC',
            params: {
                nonce: iv,
                disablePadding: true,
            },
        },
    )

    const cbcDecrypted = await provider.decryptSymmetric(
        cbcCiphertext,
        key256,
        {
            type: 'AES_256_CBC',
            params: {
                nonce: iv,
                disablePadding: true,
            },
        },
    )

    console.log('Original length:', blockAlignedData.length)
    console.log('Decrypted length:', cbcDecrypted.length)
    console.log(
        'Data match:',
        Array.from(blockAlignedData).join(',') ===
            Array.from(cbcDecrypted).join(','),
    )

    // Example 4: Standard algorithms still work
    console.log('\n=== Standard Algorithms (Fallback) ===')
    const sha256Hash = await provider.digest(data, 'SHA-256')
    console.log(
        'SHA-256:',
        Array.from(sha256Hash)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(''),
    )
}

// Execute the demonstration
demonstrateUsage().catch(console.error)

// Run the demonstration
demonstrateUsage().catch(console.error)
