// Using less common algorithms

// Make sure to import the extended crypto module to enable these algorithms
import 'pki-lite-crypto-extended'

import { AlgorithmIdentifier } from 'pki-lite/algorithms/AlgorithmIdentifier'

const algorithm = AlgorithmIdentifier.contentEncryptionAlgorithm({
    type: 'SHA1_3DES_3KEY_CBC',
    params: {
        salt: new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]),
        iterationCount: 2048,
    },
})

console.log('Algorithm OID:', algorithm.algorithm.toString())

const toBeEncrypted = new TextEncoder().encode('Hello, World!')
const encrypted = await algorithm.encrypt(
    toBeEncrypted,
    'password', // Can also be a Uint8Array
)

const decrypted = await algorithm.decrypt(
    encrypted,
    'password', // Can also be a Uint8Array
)
console.log('Decrypted data:', new TextDecoder().decode(decrypted))
