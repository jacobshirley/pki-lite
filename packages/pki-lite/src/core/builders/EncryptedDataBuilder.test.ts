import { describe, expect, it } from 'vitest'
import { EncryptedData } from '../../pkcs7/EncryptedData.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { OIDs } from '../OIDs.js'

describe('EncryptedDataBuilder', () => {
    const testData = new TextEncoder().encode('Hello, World!')
    const password = 'test-password'

    it('builds EncryptedData with default PBES2 algorithm', async () => {
        const encryptedData = await EncryptedData.builder()
            .setContentTypeOid(OIDs.PKCS7.DATA)
            .setData(testData)
            .setPassword(password)
            .build()

        expect(encryptedData.version).toBe(0)
        expect(encryptedData.encryptedContentInfo.contentType.value).toBe(
            OIDs.PKCS7.DATA,
        )
        expect(
            encryptedData.encryptedContentInfo.encryptedContent,
        ).toBeDefined()
        expect(
            encryptedData.encryptedContentInfo.encryptedContent,
        ).toBeInstanceOf(OctetString)
    })

    it('builds EncryptedData with custom algorithm params', async () => {
        const iv = crypto.getRandomValues(new Uint8Array(16))

        const encryptedData = await EncryptedData.builder()
            .setContentTypeOid(OIDs.PKCS7.DATA)
            .setData(testData)
            .setPassword(password)
            .setAlgorithm({
                type: 'PBES2',
                params: {
                    derivationAlgorithm: {
                        type: 'PBKDF2',
                        params: {
                            salt: crypto.getRandomValues(new Uint8Array(16)),
                            iterationCount: 4096,
                            hash: 'SHA-512',
                        },
                    },
                    encryptionAlgorithm: {
                        type: 'AES_256_CBC',
                        params: { nonce: iv },
                    },
                },
            })
            .build()

        expect(encryptedData.version).toBe(0)
        expect(encryptedData.encryptedContentInfo.contentType.value).toBe(
            OIDs.PKCS7.DATA,
        )
        expect(
            encryptedData.encryptedContentInfo.encryptedContent,
        ).toBeDefined()
    })

    it('builds EncryptedData with ContentEncryptionAlgorithmIdentifier', async () => {
        const algorithm = AlgorithmIdentifier.contentEncryptionAlgorithm({
            type: 'PBES2',
            params: {
                derivationAlgorithm: {
                    type: 'PBKDF2',
                    params: {
                        salt: crypto.getRandomValues(new Uint8Array(16)),
                        iterationCount: 8192,
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

        const encryptedData = await EncryptedData.builder()
            .setContentTypeOid(OIDs.PKCS7.DATA)
            .setData(testData)
            .setPassword(password)
            .setAlgorithm(algorithm)
            .build()

        expect(encryptedData.version).toBe(0)
        expect(encryptedData.encryptedContentInfo.contentType.value).toBe(
            OIDs.PKCS7.DATA,
        )
        expect(
            encryptedData.encryptedContentInfo.contentEncryptionAlgorithm,
        ).toBeDefined()
        expect(
            encryptedData.encryptedContentInfo.contentEncryptionAlgorithm
                .algorithm.value,
        ).toBe(algorithm.algorithm.value)
    })

    it('respects custom salt and IV when using default algorithm', async () => {
        const customSalt = crypto.getRandomValues(new Uint8Array(16))
        const customIV = crypto.getRandomValues(new Uint8Array(16))

        const encryptedData = await EncryptedData.builder()
            .setContentTypeOid(OIDs.PKCS7.DATA)
            .setData(testData)
            .setPassword(password)
            .setSalt(customSalt)
            .setIV(customIV)
            .setIterations(4096)
            .build()

        expect(encryptedData.version).toBe(0)
        expect(
            encryptedData.encryptedContentInfo.encryptedContent,
        ).toBeDefined()
    })

    it('throws when content type is missing', async () => {
        await expect(
            EncryptedData.builder()
                .setData(testData)
                .setPassword(password)
                .build(),
        ).rejects.toThrow('Content type is required')
    })

    it('throws when data is missing', async () => {
        await expect(
            EncryptedData.builder()
                .setContentTypeOid(OIDs.PKCS7.DATA)
                .setPassword(password)
                .build(),
        ).rejects.toThrow('Data is required')
    })

    it('throws when password is missing', async () => {
        await expect(
            EncryptedData.builder()
                .setContentTypeOid(OIDs.PKCS7.DATA)
                .setData(testData)
                .build(),
        ).rejects.toThrow('Password is required')
    })
})
