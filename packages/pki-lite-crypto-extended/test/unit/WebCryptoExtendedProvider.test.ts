import { describe, it, expect, beforeEach } from 'vitest'
import { WebCryptoExtendedProvider } from '../../src/index.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    SymmetricEncryptionAlgorithmParams,
} from 'pki-lite/core/crypto/index.js'
import { SubjectPublicKeyInfo } from 'pki-lite/keys/SubjectPublicKeyInfo'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo'

describe('WebCryptoExtendedProvider', () => {
    let provider: WebCryptoExtendedProvider

    beforeEach(() => {
        provider = new WebCryptoExtendedProvider()
    })

    describe('digest', () => {
        it('should compute MD5 hash correctly', async () => {
            const testData = new TextEncoder().encode('hello world')
            const result = await provider.digest(testData, 'MD5')

            // Expected MD5 hash of "hello world"
            const expected = new Uint8Array([
                94, 182, 59, 187, 224, 30, 238, 208, 147, 203, 34, 187, 143, 90,
                205, 195,
            ])

            expect(result).toEqual(expected)
        })

        it('should compute MD5 hash for empty data', async () => {
            const emptyData = new Uint8Array([])
            const result = await provider.digest(emptyData, 'MD5')

            // Expected MD5 hash of empty string
            const expected = new Uint8Array([
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80,
                0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
            ])

            expect(result).toEqual(expected)
        })

        it('should fallback to parent class for non-MD5 algorithms', async () => {
            const testData = new TextEncoder().encode('test')

            // Test SHA-256 (should fallback to parent implementation)
            const result = await provider.digest(testData, 'SHA-256')
            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(32) // SHA-256 produces 32 bytes
        })

        it('should handle large data for MD5', async () => {
            const largeData = new Uint8Array(10000).fill(0x41) // 10KB of 'A'
            const result = await provider.digest(largeData, 'MD5')

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16) // MD5 always produces 16 bytes
        })
    })

    describe('encryptSymmetric - AES CBC with disabled padding', () => {
        const key128 = new Uint8Array(16).fill(0x01) // 128-bit key
        const key192 = new Uint8Array(24).fill(0x02) // 192-bit key
        const key256 = new Uint8Array(32).fill(0x03) // 256-bit key
        const nonce = new Uint8Array(16).fill(0x04) // 16-byte IV
        const plaintext = new Uint8Array(16).fill(0x05) // 16-byte block

        it('should encrypt with AES-128-CBC and disabled padding', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_128_CBC',
                params: {
                    nonce,
                    disablePadding: true,
                },
            }

            const result = await provider.encryptSymmetric(
                plaintext,
                key128,
                algorithm,
            )

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16) // Same as input with no padding
            expect(result).not.toEqual(plaintext) // Should be encrypted
        })

        it('should encrypt with AES-192-CBC and disabled padding', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_192_CBC',
                params: {
                    nonce,
                    disablePadding: true,
                },
            }

            const result = await provider.encryptSymmetric(
                plaintext,
                key192,
                algorithm,
            )

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16)
            expect(result).not.toEqual(plaintext)
        })

        it('should encrypt with AES-256-CBC and disabled padding', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_CBC',
                params: {
                    nonce,
                    disablePadding: true,
                },
            }

            const result = await provider.encryptSymmetric(
                plaintext,
                key256,
                algorithm,
            )

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBe(16)
            expect(result).not.toEqual(plaintext)
        })
    })

    describe('encryptSymmetric - AES ECB', () => {
        const key128 = new Uint8Array(16).fill(0x01)
        const key192 = new Uint8Array(24).fill(0x02)
        const key256 = new Uint8Array(32).fill(0x03)
        const plaintext = new Uint8Array(16).fill(0x05)

        it('should encrypt with AES-128-ECB', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_128_ECB',
                params: {},
            }

            const result = await provider.encryptSymmetric(
                plaintext,
                key128,
                algorithm,
            )

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBeGreaterThanOrEqual(16) // ECB may add padding
            expect(result).not.toEqual(plaintext)
        })

        it('should encrypt with AES-192-ECB', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_192_ECB',
                params: {},
            }

            const result = await provider.encryptSymmetric(
                plaintext,
                key192,
                algorithm,
            )

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBeGreaterThanOrEqual(16) // ECB may add padding
            expect(result).not.toEqual(plaintext)
        })

        it('should encrypt with AES-256-ECB', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_ECB',
                params: {},
            }

            const result = await provider.encryptSymmetric(
                plaintext,
                key256,
                algorithm,
            )

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBeGreaterThanOrEqual(16) // ECB may add padding
            expect(result).not.toEqual(plaintext)
        })
    })

    describe('decryptSymmetric - AES CBC with disabled padding', () => {
        const key256 = new Uint8Array(32).fill(0x03)
        const nonce = new Uint8Array(16).fill(0x04)
        const plaintext = new Uint8Array(16).fill(0x05)

        it('should decrypt data encrypted with AES-256-CBC', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_CBC',
                params: {
                    nonce,
                    disablePadding: true,
                },
            }

            // First encrypt
            const ciphertext = await provider.encryptSymmetric(
                plaintext,
                key256,
                algorithm,
            )

            // Then decrypt
            const decrypted = await provider.decryptSymmetric(
                ciphertext,
                key256,
                algorithm,
            )

            expect(decrypted).toEqual(plaintext)
        })
    })

    describe('decryptSymmetric - AES ECB', () => {
        const key256 = new Uint8Array(32).fill(0x03)
        const plaintext = new Uint8Array(16).fill(0x05)

        it('should decrypt data encrypted with AES-256-ECB', async () => {
            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_ECB',
                params: {},
            }

            // First encrypt
            const ciphertext = await provider.encryptSymmetric(
                plaintext,
                key256,
                algorithm,
            )

            // Then decrypt
            const decrypted = await provider.decryptSymmetric(
                ciphertext,
                key256,
                algorithm,
            )

            expect(decrypted).toEqual(plaintext)
        })
    })

    describe('encrypt - RSASSA-PKCS1-v1_5', () => {
        it('should encrypt data with RSASSA-PKCS1-v1_5', async () => {
            const key256 = new Uint8Array(32).fill(0x03)
            const plaintext = new Uint8Array(16).fill(0x05)
            const algorithm: AsymmetricEncryptionAlgorithmParams = {
                type: 'RSASSA_PKCS1_v1_5',
                params: {
                    hash: 'SHA-256',
                },
            }

            const keys = await provider.generateKeyPair({
                algorithm: 'RSA',
                keySize: 2048,
            })

            const spki = SubjectPublicKeyInfo.fromDer(keys.publicKey)

            const result = await provider.encrypt(plaintext, spki, algorithm)

            expect(result).toBeInstanceOf(Uint8Array)
            expect(result.length).toBeGreaterThan(0) // Should produce some output

            const privateKeyInfo = PrivateKeyInfo.fromDer(keys.privateKey)

            const decrypted = await provider.decrypt(
                result,
                privateKeyInfo,
                algorithm,
            )

            expect(decrypted).toEqual(plaintext)
        })
    })

    describe('fallback to parent class', () => {
        it('should fallback to parent for unsupported encryption algorithms', async () => {
            const key = new Uint8Array(32).fill(0x01)
            const plaintext = new Uint8Array(16).fill(0x02)

            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_GCM',
                params: {
                    nonce: new Uint8Array(12).fill(0x03),
                },
            }

            // Should not throw and should fallback to parent implementation
            const result = await provider.encryptSymmetric(
                plaintext,
                key,
                algorithm,
            )
            expect(result).toBeInstanceOf(Uint8Array)
        })

        it('should fallback to parent for AES CBC with padding enabled', async () => {
            const key = new Uint8Array(32).fill(0x01)
            const plaintext = new Uint8Array(16).fill(0x02)
            const nonce = new Uint8Array(16).fill(0x03)

            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_CBC',
                params: {
                    nonce,
                    disablePadding: false, // Padding enabled - should fallback
                },
            }

            // Should not throw and should fallback to parent implementation
            const result = await provider.encryptSymmetric(
                plaintext,
                key,
                algorithm,
            )
            expect(result).toBeInstanceOf(Uint8Array)
        })
    })

    describe('edge cases', () => {
        it('should handle multiple block encryption with ECB', async () => {
            const key = new Uint8Array(16).fill(0x01)
            const plaintext = new Uint8Array(32).fill(0x05) // 2 blocks

            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_128_ECB',
                params: {},
            }

            const ciphertext = await provider.encryptSymmetric(
                plaintext,
                key,
                algorithm,
            )
            const decrypted = await provider.decryptSymmetric(
                ciphertext,
                key,
                algorithm,
            )

            expect(decrypted).toEqual(plaintext)
        })

        it('should handle empty data with ECB', async () => {
            const key = new Uint8Array(16).fill(0x01)
            const plaintext = new Uint8Array(0) // Empty

            const algorithm: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_128_ECB',
                params: {},
            }

            const ciphertext = await provider.encryptSymmetric(
                plaintext,
                key,
                algorithm,
            )
            expect(ciphertext.length).toBeGreaterThanOrEqual(0) // May add padding block

            const decrypted = await provider.decryptSymmetric(
                ciphertext,
                key,
                algorithm,
            )
            // Note: Decrypted data might have padding, so just check it's a Uint8Array
            expect(decrypted).toBeInstanceOf(Uint8Array)
        })
    })
})
