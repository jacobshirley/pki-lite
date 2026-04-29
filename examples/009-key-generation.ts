// Generating RSA and EC key pairs

import { KeyGen } from 'pki-lite/core/KeyGen.js'

// Generate an RSA key pair with 2048-bit key size
console.log('Generating RSA-2048 key pair...')
const rsaKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })

console.log('RSA Private Key (PEM):')
console.log(rsaKeyPair.privateKey.toPem())
console.log('\nRSA Public Key (PEM):')
console.log(rsaKeyPair.publicKey.toPem())

// Generate an ECDSA key pair using P-256 curve
console.log('\n\nGenerating ECDSA P-256 key pair...')
const ecKeyPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })

console.log('EC Private Key (PEM):')
console.log(ecKeyPair.privateKey.toPem())
console.log('\nEC Public Key (PEM):')
console.log(ecKeyPair.publicKey.toPem())

// Generate an ECDSA key pair using P-384 curve
console.log('\n\nGenerating ECDSA P-384 key pair...')
const ecP384KeyPair = await KeyGen.generateEcPair({ namedCurve: 'P-384' })

console.log('EC P-384 Private Key (PEM):')
console.log(ecP384KeyPair.privateKey.toPem())

// You can also extract the raw key objects
const privateKey = rsaKeyPair.privateKey.getPrivateKey()
console.log('\n\nRSA Private Key type:', privateKey.constructor.name)

const ecPrivateKey = ecKeyPair.privateKey.getPrivateKey()
console.log('EC Private Key type:', ecPrivateKey.constructor.name)
