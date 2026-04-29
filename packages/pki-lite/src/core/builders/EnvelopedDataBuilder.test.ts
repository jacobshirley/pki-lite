import { describe, expect, test } from 'vitest'
import { EnvelopedData } from '../../pkcs7/EnvelopedData.js'
import { Certificate } from '../../x509/Certificate.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { KeyTransRecipientInfo } from '../../pkcs7/recipients/KeyTransRecipientInfo.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { OIDs } from '../OIDs.js'

describe('EnvelopedDataBuilder', () => {
    test('can create enveloped data with single recipient', async () => {
        const data = 'Confidential message'
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const recipientKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient({ certificate: recipientCert })
            .build()

        expect(envelopedData).toBeInstanceOf(EnvelopedData)
        expect(envelopedData.recipientInfos).toHaveLength(1)
        expect(
            envelopedData.encryptedContentInfo.encryptedContent,
        ).toBeDefined()

        // Verify decryption
        const decrypted = await envelopedData.decrypt(recipientKey)
        expect(new TextDecoder().decode(decrypted)).toBe(data)
    })

    test('can create enveloped data with Uint8Array data', async () => {
        const data = new TextEncoder().encode('Binary data')
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const recipientKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient({ certificate: recipientCert })
            .build()

        expect(envelopedData).toBeInstanceOf(EnvelopedData)

        const decrypted = await envelopedData.decrypt(recipientKey)
        expect(decrypted).toEqual(data)
    })

    test('can create enveloped data with multiple recipients', async () => {
        const data = 'Shared secret'
        const recipient1Cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const recipient2Cert = Certificate.fromPem(rsaSigningKeys.caCertPem)
        const recipientKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient({ certificate: recipient1Cert })
            .addRecipient({ certificate: recipient2Cert })
            .build()

        expect(envelopedData.recipientInfos).toHaveLength(2)

        // Either recipient should be able to decrypt
        const decrypted = await envelopedData.decrypt(recipientKey)
        expect(new TextDecoder().decode(decrypted)).toBe(data)
    })

    test('can set custom key encryption algorithm', async () => {
        const data = 'Secret data'
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const recipientKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient({
                certificate: recipientCert,
                keyEncryptionAlgorithm: {
                    type: 'RSA_OAEP',
                    params: { hash: 'SHA-256' },
                },
            })
            .build()

        const recipient = envelopedData.recipientInfos[0]
        expect(recipient).toBeInstanceOf(KeyTransRecipientInfo)
        if (recipient instanceof KeyTransRecipientInfo) {
            expect(recipient.keyEncryptionAlgorithm.algorithm.toString()).toBe(
                OIDs.RSA.RSAES_OAEP,
            )
        }

        const decrypted = await envelopedData.decrypt(recipientKey)
        expect(new TextDecoder().decode(decrypted)).toBe(data)
    })

    test('can set custom content type', async () => {
        const data = 'Test content'
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .setContentType(OIDs.PKCS7.DATA)
            .addRecipient({ certificate: recipientCert })
            .build()

        expect(envelopedData.encryptedContentInfo.contentType.toString()).toBe(
            OIDs.PKCS7.DATA,
        )
    })

    test('can convert to CMS ContentInfo', async () => {
        const data = 'Test data'
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient({ certificate: recipientCert })
            .build()

        const cms = envelopedData.toCms()
        expect(cms.contentType.toString()).toBe(OIDs.PKCS7.ENVELOPED_DATA)

        // Should be able to parse back
        const parsed = EnvelopedData.fromCms(cms)
        expect(parsed).toBeInstanceOf(EnvelopedData)
        expect(parsed.recipientInfos).toHaveLength(1)
    })

    test('throws error when no data is set', async () => {
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)

        await expect(
            EnvelopedData.builder()
                .addRecipient({ certificate: recipientCert })
                .build(),
        ).rejects.toThrow()
    })

    test('throws error when no recipients are added', async () => {
        const data = 'Test data'

        await expect(
            EnvelopedData.builder().setData(data).build(),
        ).rejects.toThrow()
    })

    test('can add multiple recipients at once', async () => {
        const data = 'Test data'
        const recipient1Cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const recipient2Cert = Certificate.fromPem(rsaSigningKeys.caCertPem)

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient(
                { certificate: recipient1Cert },
                { certificate: recipient2Cert },
            )
            .build()

        expect(envelopedData.recipientInfos).toHaveLength(2)
    })

    test('encrypted content is different from plaintext', async () => {
        const data = 'Sensitive information'
        const recipientCert = Certificate.fromPem(rsaSigningKeys.certPem)

        const envelopedData = await EnvelopedData.builder()
            .setData(data)
            .addRecipient({ certificate: recipientCert })
            .build()

        const encryptedContent =
            envelopedData.encryptedContentInfo.encryptedContent
        expect(encryptedContent).toBeDefined()
        expect(encryptedContent).not.toEqual(new TextEncoder().encode(data))
    })
})
