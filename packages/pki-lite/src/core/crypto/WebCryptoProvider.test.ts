import { describe, it, expect, vi, beforeEach } from 'vitest'
import { WebCryptoProvider } from './WebCryptoProvider.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { ecP256SigningKeys } from '../../../test-fixtures/signing-keys/ec-p256/index.js'
import { Certificate } from '../../x509/Certificate.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    PbeAlgorithmParams,
    SymmetricEncryptionAlgorithmParams,
} from './types.js'

function bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes)
}

describe('WebCryptoProvider', () => {
    let provider: WebCryptoProvider = new WebCryptoProvider()

    describe('digest', () => {
        it('should call crypto.subtle.digest with correct algorithm', async () => {
            const data = new TextEncoder().encode('lolface')

            const result = await provider.digest(data, 'SHA-256')

            expect(bytesToString(result)).toMatchInlineSnapshot(
                `"\`.�?�Z�1�H�e�2���4ח?-8�i��0IiZ"`,
            )
        })
    })

    describe('sign', () => {
        describe('RSA signing', () => {
            it('should sign data with the correct algorithm', async () => {
                const data = new TextEncoder().encode('test')
                const privateKey = PrivateKeyInfo.fromDer(
                    rsaSigningKeys.privateKey,
                )
                const result = await provider.sign(data, privateKey, {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: {
                        hash: 'SHA-256',
                    },
                })

                expect(result).toBeDefined()
                expect(bytesToString(result)).toMatchInlineSnapshot(
                    `"�{�l�"�W%�i��ŧ���S1T$�3$в|�	���1'b�[�~��J|�v؍#/���)��7t�XXfJr���W7��7L��61�<&�%�ɀ��#����R	7!2�>�x��[@��r܏��o�c�H�($�Ɓ �؎3qΥ�,��(|����{[�c��)����jZ#^�i�dYׯC��r�x�ύ�:�B��TTyF��)E��I!�9|�8���tk��y�ư�yrs��s͈�[ŻΈ\\����"`,
                )
            })
        })

        describe('ECDSA signing', () => {
            it('should sign data with the correct algorithm', async () => {
                const data = new TextEncoder().encode('test')
                const privateKey = PrivateKeyInfo.fromDer(
                    ecP256SigningKeys.privateKey,
                )
                const result = await provider.sign(data, privateKey, {
                    type: 'ECDSA',
                    params: {
                        namedCurve: 'P-256',
                        hash: 'SHA-256',
                    },
                })

                expect(result).toBeDefined()
            })
        })
    })

    describe('verify', () => {
        describe('RSA signature verification', () => {
            it('should verify a valid signature', async () => {
                const data = new TextEncoder().encode('test')
                const privateKey = PrivateKeyInfo.fromDer(
                    rsaSigningKeys.privateKey,
                )
                const cert = Certificate.fromPem(rsaSigningKeys.certPem)

                const algorithm: AsymmetricEncryptionAlgorithmParams = {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: {
                        hash: 'SHA-256',
                    },
                }

                const signature = await provider.sign(
                    data,
                    privateKey,
                    algorithm,
                )

                const valid = await provider.verify(
                    data,
                    cert.tbsCertificate.subjectPublicKeyInfo,
                    signature,
                    algorithm,
                )

                expect(valid).toBe(true)
            })

            it('should fail verification for tampered data', async () => {
                const data = new TextEncoder().encode('test')
                const tamperedData = new TextEncoder().encode('tampered data')
                const privateKey = PrivateKeyInfo.fromDer(
                    rsaSigningKeys.privateKey,
                )
                const cert = Certificate.fromPem(rsaSigningKeys.certPem)

                const algorithm: AsymmetricEncryptionAlgorithmParams = {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: {
                        hash: 'SHA-256',
                    },
                }

                const signature = await provider.sign(
                    data,
                    privateKey,
                    algorithm,
                )

                const valid = await provider.verify(
                    tamperedData,
                    cert.tbsCertificate.subjectPublicKeyInfo,
                    signature,
                    algorithm,
                )

                expect(valid).toBe(false)
            })
        })

        describe('ECDSA signature verification', () => {
            it('should verify a valid signature', async () => {
                const data = new TextEncoder().encode('test')
                const privateKey = PrivateKeyInfo.fromDer(
                    ecP256SigningKeys.privateKey,
                )
                const cert = Certificate.fromPem(ecP256SigningKeys.certPem)

                const algorithm = {
                    type: 'ECDSA',
                    params: {
                        namedCurve: 'P-256',
                        hash: 'SHA-256',
                    },
                } as const

                const signature = await provider.sign(
                    data,
                    privateKey,
                    algorithm,
                )

                const valid = await provider.verify(
                    data,
                    cert.tbsCertificate.subjectPublicKeyInfo,
                    signature,
                    algorithm,
                )

                expect(valid).toBe(true)
            })

            it('should fail verification for tampered data', async () => {
                const data = new TextEncoder().encode('test')
                const tamperedData = new TextEncoder().encode('tampered data')
                const privateKey = PrivateKeyInfo.fromDer(
                    ecP256SigningKeys.privateKey,
                )
                const cert = Certificate.fromPem(ecP256SigningKeys.certPem)

                const algorithm = {
                    type: 'ECDSA',
                    params: {
                        namedCurve: 'P-256',
                        hash: 'SHA-256',
                    },
                } as const

                const signature = await provider.sign(
                    data,
                    privateKey,
                    algorithm,
                )

                const valid = await provider.verify(
                    tamperedData,
                    cert.tbsCertificate.subjectPublicKeyInfo,
                    signature,
                    algorithm,
                )

                expect(valid).toBe(false)
            })
        })
    })

    describe('encryptSymmetric/decryptSymmetric', () => {
        it('should encrypt and decrypt data symmetrically', async () => {
            const data = new TextEncoder().encode('test')
            const key = crypto.getRandomValues(new Uint8Array(16)) // AES-128

            const encryption: SymmetricEncryptionAlgorithmParams = {
                type: 'AES_256_CBC',
                params: {
                    nonce: crypto.getRandomValues(new Uint8Array(16)),
                },
            } as const

            const encrypted = await provider.encryptSymmetric(
                data,
                key,
                encryption,
            )

            expect(encrypted).toBeDefined()

            const decrypted = await provider.decryptSymmetric(
                encrypted,
                key,
                encryption,
            )

            expect(bytesToString(decrypted)).toBe('test')
        })

        it('should be able to handle PBE encryption and decryption', async () => {
            const data = new TextEncoder().encode('test')
            const password = 'strongpassword'

            const encryption: PbeAlgorithmParams = {
                type: 'PBES2',
                params: {
                    derivationAlgorithm: {
                        type: 'PBKDF2',
                        params: {
                            salt: crypto.getRandomValues(new Uint8Array(16)),
                            iterationCount: 10000,
                            hash: 'SHA-256',
                            keyLength: 16,
                        },
                    },
                    encryptionAlgorithm: {
                        type: 'AES_256_CBC',
                        params: {
                            nonce: crypto.getRandomValues(new Uint8Array(16)),
                        },
                    },
                },
            }

            const encrypted = await provider.encryptSymmetric(
                data,
                password,
                encryption,
            )

            expect(encrypted).toBeDefined()

            const decrypted = await provider.decryptSymmetric(
                encrypted,
                password,
                encryption,
            )

            expect(bytesToString(decrypted)).toBe('test')
        })
    })
})
