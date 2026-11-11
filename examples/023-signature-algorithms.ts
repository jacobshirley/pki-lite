// Choosing signature algorithms: RSA, RSA-PSS, ECDSA and Ed25519

import { KeyGen } from 'pki-lite/core/KeyGen.js'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from 'pki-lite/keys/SubjectPublicKeyInfo.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

console.log('=== Signature Algorithms Example ===\n')

async function selfSigned(
    name: string,
    keys: { privateKey: PrivateKeyInfo; publicKey: SubjectPublicKeyInfo },
    algorithm: Parameters<
        ReturnType<typeof Certificate.builder>['setAlgorithm']
    >[0],
) {
    const certificate = await Certificate.builder()
        .setSubject(`CN=${name}`)
        .setPublicKey(keys.publicKey)
        .setPrivateKey(keys.privateKey)
        .setAlgorithm(algorithm)
        .setValidityDays(30)
        .generateSerialNumber()
        .selfSign()

    // Check the signature we just made, and report what was used
    const valid = await certificate.isSelfSigned()
    console.log(
        `${name.padEnd(22)} ${certificate.signatureAlgorithm.algorithm.friendlyName}`.padEnd(
            58,
        ),
        `signature valid: ${valid}`,
    )
}

// RSA: the classic PKCS#1 v1.5 padding, or the newer, randomised PSS
const rsa = await KeyGen.generateRsaPair({ keySize: 2048 })
await selfSigned('RSA PKCS#1 v1.5', rsa, {
    type: 'RSASSA_PKCS1_v1_5',
    params: { hash: 'SHA-256' },
})
await selfSigned('RSA-PSS', rsa, {
    type: 'RSA_PSS',
    params: { hash: 'SHA-256', saltLength: 32 },
})

// ECDSA: the hash is chosen independently of the curve
const p256 = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
await selfSigned('ECDSA P-256 / SHA-256', p256, {
    type: 'ECDSA',
    params: { namedCurve: 'P-256', hash: 'SHA-256' },
})
const p384 = await KeyGen.generateEcPair({ namedCurve: 'P-384' })
await selfSigned('ECDSA P-384 / SHA-384', p384, {
    type: 'ECDSA',
    params: { namedCurve: 'P-384', hash: 'SHA-384' },
})

// Ed25519 has no hash or other parameters. KeyGen does not generate these keys yet, so
// create one with WebCrypto (needs a runtime that supports Ed25519) and wrap it.
const ed25519 = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
])
await selfSigned(
    'Ed25519',
    {
        privateKey: PrivateKeyInfo.fromDer(
            new Uint8Array(
                await crypto.subtle.exportKey('pkcs8', ed25519.privateKey),
            ),
        ),
        publicKey: SubjectPublicKeyInfo.fromDer(
            new Uint8Array(
                await crypto.subtle.exportKey('spki', ed25519.publicKey),
            ),
        ),
    },
    { type: 'ED25519', params: {} },
)
