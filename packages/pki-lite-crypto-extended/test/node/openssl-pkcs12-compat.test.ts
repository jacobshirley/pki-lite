/**
 * @vitest-environment node
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { spawn } from 'child_process'
import {
    writeFileSync,
    readFileSync,
    unlinkSync,
    mkdirSync,
    existsSync,
    rmSync,
} from 'fs'
import { randomUUID } from 'crypto'
import { PFX } from 'pki-lite/pkcs12/PFX.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from 'pki-lite/keys/SubjectPublicKeyInfo.js'
import { RSAPublicKey } from 'pki-lite/keys/RSAPublicKey.js'
import { RSAPrivateKey } from 'pki-lite/keys/RSAPrivateKey.js'
import { setCryptoProvider } from 'pki-lite/core/crypto/provider.js'
import { WebCryptoExtendedProvider } from '../../src/crypto/WebCryptoExtendedProvider.js'
import { rsaEncrypt, rsaDecrypt } from '../../src/crypto/rsa.js'

function getTempFolder(): string {
    const tmpFolder = `/tmp/pki-lite-openssl-pkcs12-${randomUUID()}`
    if (!existsSync(tmpFolder)) {
        mkdirSync(tmpFolder, { recursive: true })
    }
    return tmpFolder
}

async function runOpenSSL(args: string[], tmpFolder: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        // Use Docker with alpine/openssl which supports legacy algorithms better
        const dockerOpenssl = `docker run --rm -v ${tmpFolder}:/data -w /data alpine/openssl:latest`
        writeFileSync(
            tmpFolder + '/debug.sh',
            `${dockerOpenssl} ${args.map((x) => x.replace(tmpFolder + '/', '')).join(' ')}`,
            {
                mode: 0o755,
            },
        )

        const child = spawn('./debug.sh', { cwd: tmpFolder, shell: true })

        const output: Buffer[] = []
        const error: Buffer[] = []

        child.stdout.on('data', (chunk) => output.push(chunk))
        child.stderr.on('data', (chunk) => error.push(chunk))

        child.on('close', (code) => {
            if (code === 0) {
                resolve(Buffer.concat(output))
            } else {
                reject(
                    new Error(
                        `OpenSSL exited with code ${code}: ${Buffer.concat(error).toString()}`,
                    ),
                )
            }
        })
    })
}

describe('OpenSSL PKCS#12 Compatibility', { timeout: 30000 }, () => {
    const password = 'test-password-123'

    beforeAll(() => {
        // Use extended crypto provider to support PKCS#12 PBE algorithms
        setCryptoProvider(new WebCryptoExtendedProvider())
    })

    it('can parse PKCS#12 file created by OpenSSL with PBE-SHA1-3DES', async () => {
        const tmpFolder = getTempFolder()

        try {
            // Create a test certificate and key with OpenSSL
            await runOpenSSL(
                [
                    'req',
                    '-x509',
                    '-newkey',
                    'rsa:2048',
                    '-keyout',
                    'key.pem',
                    '-out',
                    'cert.pem',
                    '-days',
                    '1',
                    '-nodes',
                    '-subj',
                    '/CN=Test',
                ],
                tmpFolder,
            )

            // Create PKCS#12 file using 3DES-CBC with PKCS#12 KDF
            // -keypbe PBE-SHA1-3DES uses SHA1 with 3-key triple DES
            await runOpenSSL(
                [
                    'pkcs12',
                    '-export',
                    '-out',
                    'test.p12',
                    '-inkey',
                    'key.pem',
                    '-in',
                    'cert.pem',
                    '-passout',
                    `pass:${password}`,
                    '-keypbe',
                    'PBE-SHA1-3DES',
                    '-certpbe',
                    'PBE-SHA1-3DES',
                    '-macalg',
                    'sha1',
                ],
                tmpFolder,
            )

            const pfxData = readFileSync(`${tmpFolder}/test.p12`)

            // Verify OpenSSL can parse it
            await runOpenSSL(
                [
                    'pkcs12',
                    '-in',
                    'test.p12',
                    '-passin',
                    `pass:${password}`,
                    '-nodes',
                    '-noout',
                ],
                tmpFolder,
            )

            // Now parse with our implementation
            const pfx = PFX.fromDer(pfxData)
            const bags = await pfx.getBags(password)

            // Should have at least one key and one certificate
            const keyBags = bags.filter(
                (b) => b.bagId.value === '1.2.840.113549.1.12.10.1.2',
            )
            const certBags = bags.filter(
                (b) => b.bagId.value === '1.2.840.113549.1.12.10.1.3',
            )

            expect(keyBags.length).toBeGreaterThan(0)
            expect(certBags.length).toBeGreaterThan(0)
        } finally {
            // Cleanup
            try {
                rmSync(tmpFolder, { recursive: true, force: true })
            } catch {}
        }
    })
})

describe('OpenSSL RSA PKCS#1 v1.5 Encryption', { timeout: 30000 }, () => {
    beforeAll(() => {
        // Use extended crypto provider to support custom RSA encryption
        setCryptoProvider(new WebCryptoExtendedProvider())
    })

    it('can encrypt data that OpenSSL can decrypt with PKCS#1 v1.5', async () => {
        const tmpFolder = getTempFolder()

        try {
            // Generate RSA key pair with OpenSSL
            await runOpenSSL(
                ['genrsa', '-out', 'private.pem', '2048'],
                tmpFolder,
            )

            // Extract public key
            await runOpenSSL(
                ['rsa', '-in', 'private.pem', '-pubout', '-out', 'public.pem'],
                tmpFolder,
            )

            // Read the public key
            const publicKeyPem = readFileSync(
                `${tmpFolder}/public.pem`,
                'utf-8',
            )
            const publicKeyInfo = SubjectPublicKeyInfo.fromPem(publicKeyPem)
            const publicKey = publicKeyInfo.getPublicKey()

            if (!(publicKey instanceof RSAPublicKey)) {
                throw new Error('Expected RSAPublicKey')
            }

            // Encrypt with our implementation
            const plaintext = 'Hello from our custom RSA implementation!'
            const plaintextBytes = new TextEncoder().encode(plaintext)
            const encrypted = rsaEncrypt(plaintextBytes, publicKey)

            // Write encrypted data
            writeFileSync(`${tmpFolder}/encrypted.bin`, encrypted)

            // Decrypt with OpenSSL using pkcs1 padding
            await runOpenSSL(
                [
                    'pkeyutl',
                    '-decrypt',
                    '-in',
                    'encrypted.bin',
                    '-inkey',
                    'private.pem',
                    '-pkeyopt',
                    'rsa_padding_mode:pkcs1',
                    '-out',
                    'decrypted.txt',
                ],
                tmpFolder,
            )

            // Read decrypted content
            const decrypted = readFileSync(
                `${tmpFolder}/decrypted.txt`,
                'utf-8',
            )

            // Verify OpenSSL decrypted it correctly
            expect(decrypted).toBe(plaintext)
        } finally {
            // Cleanup
            try {
                rmSync(tmpFolder, { recursive: true, force: true })
            } catch {}
        }
    })

    it('can decrypt data encrypted by OpenSSL with PKCS#1 v1.5', async () => {
        const tmpFolder = getTempFolder()

        try {
            // Generate RSA key pair with OpenSSL
            await runOpenSSL(
                ['genrsa', '-out', 'private.pem', '2048'],
                tmpFolder,
            )

            // Extract public key
            await runOpenSSL(
                ['rsa', '-in', 'private.pem', '-pubout', '-out', 'public.pem'],
                tmpFolder,
            )

            // Create plaintext
            const plaintext = 'Hello from OpenSSL!'
            writeFileSync(`${tmpFolder}/plaintext.txt`, plaintext)

            // Encrypt with OpenSSL using pkcs1 padding
            await runOpenSSL(
                [
                    'pkeyutl',
                    '-encrypt',
                    '-in',
                    'plaintext.txt',
                    '-pubin',
                    '-inkey',
                    'public.pem',
                    '-pkeyopt',
                    'rsa_padding_mode:pkcs1',
                    '-out',
                    'encrypted.bin',
                ],
                tmpFolder,
            )

            // Read encrypted data and private key
            const encrypted = readFileSync(`${tmpFolder}/encrypted.bin`)
            const privateKeyPem = readFileSync(
                `${tmpFolder}/private.pem`,
                'utf-8',
            )
            const privateKeyInfo = PrivateKeyInfo.fromPem(privateKeyPem)
            const privateKey = privateKeyInfo.getPrivateKey()

            if (!(privateKey instanceof RSAPrivateKey)) {
                throw new Error('Expected RSAPrivateKey')
            }

            // Decrypt with our implementation
            const decrypted = rsaDecrypt(encrypted, privateKey)

            // Verify we decrypted it correctly
            expect(new TextDecoder().decode(decrypted)).toBe(plaintext)
        } finally {
            // Cleanup
            try {
                rmSync(tmpFolder, { recursive: true, force: true })
            } catch {}
        }
    })
})
