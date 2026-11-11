import { describe, it, expect, vi, beforeEach } from 'vitest'
import { WebCryptoProvider } from './WebCryptoProvider.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { ecP256SigningKeys } from '../../../test-fixtures/signing-keys/ec-p256/index.js'
import { Certificate } from '../../x509/Certificate.js'
import { opensslCorpus } from '../../../test-fixtures/openssl-corpus/corpus.js'
import { OIDs } from '../OIDs.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import {
    AsymmetricEncryptionAlgorithmParams,
    PbeAlgorithmParams,
    SymmetricEncryptionAlgorithmParams,
} from './types.js'

function bytesToString(bytes: Uint8Array<ArrayBuffer>): string {
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
                    `
                  "if�U
                  nߗ0�c:��ޑˋ<���s�b��Vȡ3�q�,��Y{S�X���4���Z�P�h}vu�4͹:�j���%�<�}��7��Y���7s�Y��?{؁u;f�x��Fɧ��Y��MY�5;k��ٯ�^�.Y^G�Ɲ��Ak�bNo;z��i��Pk)�/�f̠cq!7�5��ʫ�]c��/Լ�q��тU@�����!(�����C^��ch�m�g�ۥ}�j3s�w 0'lacl�~F�1FM��՛�9�,[�"
                `,
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

describe('toSymmetricEncryptionAlgorithmParams AES key sizes', () => {
    const provider = new WebCryptoProvider()
    const iv = new OctetString({ bytes: new Uint8Array(16) }).toAsn1()

    for (const bits of [128, 192, 256] as const) {
        it(`reports AES-${bits}-CBC as AES_${bits}_CBC, not AES_256_CBC`, () => {
            const params = provider.toSymmetricEncryptionAlgorithmParams(
                new AlgorithmIdentifier({
                    algorithm: OIDs.ENCRYPTION[`AES_${bits}_CBC`],
                    parameters: iv,
                }),
            )
            expect(params.type).toBe(`AES_${bits}_CBC`)
        })

        it(`reports AES-${bits}-ECB as AES_${bits}_ECB, not AES_256_ECB`, () => {
            const params = provider.toSymmetricEncryptionAlgorithmParams(
                new AlgorithmIdentifier({
                    algorithm: OIDs.ENCRYPTION[`AES_${bits}_ECB`],
                }),
            )
            expect(params.type).toBe(`AES_${bits}_ECB`)
        })
    }
})

describe('AES-GCM additional authenticated data', () => {
    const provider = new WebCryptoProvider()
    const key = new Uint8Array(32).map((_, i) => i)
    const nonce = new Uint8Array(12).map((_, i) => 100 + i)
    const data = new TextEncoder().encode('authenticated and encrypted')
    const aad = new Uint8Array([1, 2, 3, 4])

    const params = (additionalData?: Uint8Array<ArrayBuffer>) => ({
        type: 'AES_256_GCM' as const,
        params: { nonce, additionalData },
    })

    it('decrypts when the same additional data is supplied', async () => {
        const sealed = await provider.encryptSymmetric(data, key, params(aad))
        expect(
            await provider.decryptSymmetric(sealed, key, params(aad)),
        ).toEqual(data)
    })

    it('fails authentication when the additional data differs', async () => {
        const sealed = await provider.encryptSymmetric(data, key, params(aad))
        await expect(
            provider.decryptSymmetric(
                sealed,
                key,
                params(new Uint8Array([9, 9, 9, 9])),
            ),
        ).rejects.toThrow()
        await expect(
            provider.decryptSymmetric(sealed, key, params()),
        ).rejects.toThrow()
    })
})

describe('Ed25519', () => {
    const provider = new WebCryptoProvider()
    const algorithm = { type: 'ED25519' as const, params: {} }

    it('signs and verifies, and detects tampering', async () => {
        const key = PrivateKeyInfo.fromDer(
            Uint8Array.from(atob(opensslCorpus.key['pkcs8_ed25519.der']), (c) =>
                c.charCodeAt(0),
            ),
        )
        const cert = Certificate.fromDer(
            Uint8Array.from(atob(opensslCorpus.cert['key_ed25519.der']), (c) =>
                c.charCodeAt(0),
            ),
        )
        const spki = cert.getSubjectPublicKeyInfo()
        const data = new TextEncoder().encode('sign me')

        const signature = await provider.sign(data, key, algorithm)
        expect(signature).toHaveLength(64)
        expect(await provider.verify(data, spki, signature, algorithm)).toBe(
            true,
        )
        expect(
            await provider.verify(
                new TextEncoder().encode('tampered'),
                spki,
                signature,
                algorithm,
            ),
        ).toBe(false)
    })

    it('uses the RFC 8410 algorithm identifier without parameters', () => {
        const identifier = provider.signatureAlgorithm(algorithm)
        expect(identifier.algorithm.value).toBe('1.3.101.112')
        expect(identifier.parameters).toBeUndefined()
    })

    it('reports Ed448 as needing the extended provider', async () => {
        const spki = Certificate.fromDer(
            Uint8Array.from(atob(opensslCorpus.cert['key_ed448.der']), (c) =>
                c.charCodeAt(0),
            ),
        ).getSubjectPublicKeyInfo()
        await expect(
            provider.verify(new Uint8Array(1), spki, new Uint8Array(114), {
                type: 'ED448',
                params: {},
            }),
        ).rejects.toThrow('pki-lite-crypto-extended')
    })
})
