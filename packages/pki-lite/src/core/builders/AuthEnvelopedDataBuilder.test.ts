import { describe, expect, test } from 'vitest'
import { AuthEnvelopedData } from '../../pkcs7/AuthEnvelopedData.js'
import { ContentInfo } from '../../pkcs7/ContentInfo.js'
import { EnvelopedData } from '../../pkcs7/EnvelopedData.js'
import { Certificate } from '../../x509/Certificate.js'
import { Attribute } from '../../x509/Attribute.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { OIDs } from '../OIDs.js'
import { asn1js } from '../PkiBase.js'

const recipient = () => ({
    certificate: Certificate.fromPem(rsaSigningKeys.certPem),
})
const privateKey = () => PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes)

describe('AuthEnvelopedDataBuilder', () => {
    test('encrypts with AES-256-GCM and a 16-byte tag by default', async () => {
        const authEnvelopedData = await AuthEnvelopedData.builder()
            .setData('secret')
            .addRecipient(recipient())
            .build()

        expect(authEnvelopedData.version).toBe(0)
        expect(authEnvelopedData.mac).toHaveLength(16)
        expect(authEnvelopedData.authAttrs).toBeUndefined()
        expect(
            authEnvelopedData.authEncryptedContentInfo
                .contentEncryptionAlgorithm.algorithm.value,
        ).toBe(OIDs.ENCRYPTION.AES_256_GCM)
        // the ciphertext is the content without its tag
        expect(
            authEnvelopedData.authEncryptedContentInfo.encryptedContent!.bytes,
        ).toHaveLength('secret'.length)
        expect(text(await authEnvelopedData.decrypt(privateKey()))).toBe(
            'secret',
        )
    })

    test('survives a DER round trip through ContentInfo', async () => {
        const authEnvelopedData = await AuthEnvelopedData.builder()
            .setData('round trip')
            .addRecipient(recipient())
            .build()

        const der = authEnvelopedData.toCms().toDer()
        const parsed = AuthEnvelopedData.fromCms(ContentInfo.fromDer(der))
        expect(parsed.toCms().toDer()).toEqual(der)
        expect(text(await parsed.decrypt(privateKey()))).toBe('round trip')
    })

    test('writes the tag length into the GCM parameters (in bytes)', async () => {
        const authEnvelopedData = await AuthEnvelopedData.builder()
            .setData('x')
            .setContentEncryptionAlgorithm({
                type: 'AES_128_GCM',
                params: {
                    nonce: new Uint8Array(12).fill(7),
                    icvLen: 13,
                },
            })
            .addRecipient(recipient())
            .build()

        expect(authEnvelopedData.mac).toHaveLength(13)
        const params =
            authEnvelopedData.authEncryptedContentInfo.contentEncryptionAlgorithm.toSymmetricEncryptionAlgorithmParams()
        expect(params.type).toBe('AES_128_GCM')
        expect(params.params).toMatchObject({ icvLen: 13 })
        expect(text(await authEnvelopedData.decrypt(privateKey()))).toBe('x')
    })

    test('adds the content-type attribute when the content is not id-data', async () => {
        const authEnvelopedData = await AuthEnvelopedData.builder()
            .setData('signed content', OIDs.PKCS7.SIGNED_DATA)
            .addRecipient(recipient())
            .build()

        expect(authEnvelopedData.authAttrs).toHaveLength(1)
        expect(authEnvelopedData.authAttrs![0].type.value).toBe(
            OIDs.PKCS9.CONTENT_TYPE,
        )
        expect(text(await authEnvelopedData.decrypt(privateKey()))).toBe(
            'signed content',
        )
    })

    test('authenticated attributes are covered by the tag', async () => {
        const marker = new Attribute({
            type: '1.2.3.4.5',
            values: [new asn1js.Integer({ value: 42 })],
        })
        const authEnvelopedData = await AuthEnvelopedData.builder()
            .setData('attributes')
            .addAuthenticatedAttribute(marker)
            .addRecipient(recipient())
            .build()

        // supplied attribute plus the content-type one the RFC requires
        expect(authEnvelopedData.authAttrs).toHaveLength(2)

        const parsed = AuthEnvelopedData.fromDer(authEnvelopedData.toDer())
        expect(text(await parsed.decrypt(privateKey()))).toBe('attributes')

        // changing an authenticated attribute breaks authentication
        const tampered = AuthEnvelopedData.fromDer(authEnvelopedData.toDer())
        tampered.authAttrs = tampered.authAttrs!.map((attribute) =>
            attribute.type.value === '1.2.3.4.5'
                ? new Attribute({
                      type: '1.2.3.4.5',
                      values: [new asn1js.Integer({ value: 43 })],
                  })
                : attribute,
        ) as typeof tampered.authAttrs
        await expect(tampered.decrypt(privateKey())).rejects.toThrow()
    })

    test('is rejected by EnvelopedData rather than misread', async () => {
        const authEnvelopedData = await AuthEnvelopedData.builder()
            .setData('x')
            .addRecipient(recipient())
            .build()
        expect(() =>
            EnvelopedData.fromAsn1(authEnvelopedData.toAsn1()),
        ).toThrow(/AuthEnvelopedData/)
    })

    test('requires data, a recipient and an AES-GCM cipher', async () => {
        await expect(
            AuthEnvelopedData.builder().addRecipient(recipient()).build(),
        ).rejects.toThrow('No data to encrypt')
        await expect(
            AuthEnvelopedData.builder().setData('x').build(),
        ).rejects.toThrow('At least one recipient')
        await expect(
            AuthEnvelopedData.builder()
                .setData('x')
                .addRecipient(recipient())
                .setContentEncryptionAlgorithm({
                    type: 'AES_256_CBC',
                    params: { nonce: new Uint8Array(16) },
                } as never)
                .build(),
        ).rejects.toThrow('needs an AES-GCM cipher')
        await expect(
            AuthEnvelopedData.builder()
                .setData('x')
                .addRecipient(recipient())
                .setContentEncryptionAlgorithm({
                    type: 'AES_256_GCM',
                    params: { nonce: new Uint8Array(12), icvLen: 8 },
                })
                .build(),
        ).rejects.toThrow('12 to 16 bytes')
    })
})
