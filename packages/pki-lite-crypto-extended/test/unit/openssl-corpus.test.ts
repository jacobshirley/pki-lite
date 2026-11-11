/**
 * The OpenSSL corpus cases that need algorithms only this package provides:
 * RSA PKCS#1 v1.5 key transport (OpenSSL's default for CMS) and 3DES PKCS#12.
 * The fixtures live with pki-lite's own corpus test.
 */
import { describe, expect, test } from 'vitest'
import '../../src/index.js' // installs WebCryptoExtendedProvider
import { WebCryptoExtendedProvider } from '../../src/index.js'
import { opensslCorpus } from '../../../pki-lite/test-fixtures/openssl-corpus/corpus.js'
import { ContentInfo } from 'pki-lite/pkcs7/ContentInfo.js'
import { EnvelopedData } from 'pki-lite/pkcs7/EnvelopedData.js'
import { AuthEnvelopedData } from 'pki-lite/pkcs7/AuthEnvelopedData.js'
import { PrivateKeyInfo } from 'pki-lite/keys/PrivateKeyInfo.js'
import { PFX } from 'pki-lite/pkcs12/PFX.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'

const read = (family: string, file: string) =>
    Uint8Array.from(atob(opensslCorpus[family][file]), (c) => c.charCodeAt(0))

// OpenSSL canonicalises text content to CRLF unless -binary is used
const MESSAGE = 'Hello, CMS world\n'

describe('OpenSSL corpus with the extended provider', () => {
    test('PKCS#12 with pbeWithSHAAnd3-KeyTripleDES-CBC can be read', async () => {
        const items = await PFX.fromDer(
            read('p12', 'legacy_3des.p12'),
        ).extractItems('pw')
        expect(items.privateKeys).toHaveLength(1)
        expect(items.certificates).toHaveLength(1)
    })

    describe('EnvelopedData with RSA PKCS#1 v1.5 key transport', () => {
        const key = () => PrivateKeyInfo.fromDer(read('key', 'pkcs8_rsa.der'))
        for (const file of [
            'ed_rsa_3des.der',
            'ed_rsa_aes128.der',
            'ed_rsa_aes256.der',
            'ed_rsa_keyid.der',
        ]) {
            test(`${file} decrypts`, async () => {
                const ed = ContentInfo.fromDer(
                    read('cms', file),
                ).parseContentAs(EnvelopedData)
                const plain = await ed.decrypt(key())
                expect(
                    new TextDecoder().decode(plain).replace(/\r\n/g, '\n'),
                ).toBe(MESSAGE)
            })
        }

        for (const file of ['ed_rsa_gcm.der', 'authenveloped.der']) {
            test(`${file} (AuthEnvelopedData, AES-256-GCM) decrypts`, async () => {
                const aed = ContentInfo.fromDer(
                    read('cms', file),
                ).parseContentAs(AuthEnvelopedData)
                const plain = await aed.decrypt(key())
                expect(
                    new TextDecoder().decode(plain).replace(/\r\n/g, '\n'),
                ).toBe(MESSAGE)
            })
        }

        test('the streamed (BER) message decrypts', async () => {
            const ed = ContentInfo.fromDer(
                read('cms', 'ed_stream.der'),
            ).parseContentAs(EnvelopedData)
            expect((await ed.decrypt(key())).length).toBe(5000)
        })

        test('an empty message decrypts', async () => {
            const ed = ContentInfo.fromDer(
                read('cms', 'ed_empty.der'),
            ).parseContentAs(EnvelopedData)
            expect((await ed.decrypt(key())).length).toBe(0)
        })
    })

    test('an Ed448 certificate verifies its own signature (OpenSSL-made)', async () => {
        const cert = Certificate.fromDer(read('cert', 'key_ed448.der'))
        expect(await cert.isSelfSigned()).toBe(true)
    })

    test('an Ed448 signature round-trips and detects tampering', async () => {
        const cert = Certificate.fromDer(read('cert', 'key_ed448.der'))
        const key = PrivateKeyInfo.fromDer(read('key', 'pkcs8_ed448.der'))
        const provider = new WebCryptoExtendedProvider()
        const data = new TextEncoder().encode('sign me')
        const spki = cert.getSubjectPublicKeyInfo()
        const algorithm = { type: 'ED448' as const, params: {} }

        const signature = await provider.sign(data, key, algorithm)
        expect(signature).toHaveLength(114)
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
})
