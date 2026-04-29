import { describe, expect, test } from 'vitest'
import { SignedData } from '../../pkcs7/SignedData.js'
import { Certificate } from '../../x509/Certificate.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { CertificateList } from '../../x509/CertificateList.js'
import { OCSPResponse } from '../../ocsp/OCSPResponse.js'
import { Attribute } from '../../x509/Attribute.js'
import { OtherRevocationInfoFormat } from '../../revocation/OtherRevocationInfoFormat.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { OIDs } from '../OIDs.js'

describe('SignedDataBuilder', () => {
    test('can create attached signed data with single signer', async () => {
        const data = new TextEncoder().encode('Hello, World!')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .build()

        expect(signedData).toBeInstanceOf(SignedData)
        expect(signedData.signerInfos).toHaveLength(1)
        expect(signedData.encapContentInfo.eContent).toBeDefined()

        // Verify the signature
        const verified = await signedData.verify({ data })
        expect(verified.valid).toBe(true)
    })

    test('can create detached signed data', async () => {
        const data = new TextEncoder().encode('Detached content')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .setDetached(true)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .build()

        expect(signedData.encapContentInfo.eContent).toBeUndefined()

        // Verify with external data
        const verified = await signedData.verify({ data })
        expect(verified.valid).toBe(true)
    })

    test('can create signed data with custom algorithm', async () => {
        const data = new TextEncoder().encode('test data')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
                encryptionAlgorithm: {
                    type: 'RSASSA_PKCS1_v1_5',
                    params: { hash: 'SHA-512' },
                },
            })
            .build()

        // SHA-512 with RSA OID is 1.2.840.113549.1.1.13
        expect(
            signedData.signerInfos[0].signatureAlgorithm.algorithm.toString(),
        ).toBe('1.2.840.113549.1.1.13')

        const verified = await signedData.verify({ data })
        expect(verified.valid).toBe(true)
    })

    test('can add signed attributes', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        const signingTime = new Date('2025-01-01T00:00:00Z')

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
                signedAttrs: [
                    Attribute.signingTime(signingTime),
                    Attribute.signingLocation({
                        countryName: 'US',
                        localityName: 'Test City',
                    }),
                ],
            })
            .build()

        expect(signedData.signerInfos[0].signedAttrs).toBeDefined()
        expect(
            signedData.signerInfos[0].signedAttrs?.length,
        ).toBeGreaterThanOrEqual(2)

        const verified = await signedData.verify({ data })
        expect(verified.valid).toBe(true)
    })

    test('can add additional certificates', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
        const caCertificate = Certificate.fromPem(rsaSigningKeys.caCertPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .addCertificate(caCertificate)
            .build()

        expect(signedData.certificates).toBeDefined()
        expect(signedData.certificates?.length).toBeGreaterThanOrEqual(1)
    })

    test('can add CRL', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
        const crl = CertificateList.fromPem(rsaSigningKeys.caCrlPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .addCrl(crl)
            .build()

        expect(signedData.crls).toBeDefined()
        expect(signedData.crls?.length).toBe(1)
    })

    test('can add OCSP response', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
        const ocspResponse = OCSPResponse.fromDer(rsaSigningKeys.ocspResponse)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .addOcsp(ocspResponse)
            .build()

        expect(signedData.crls).toBeDefined()
        expect(
            signedData.crls?.some(
                (crl) => crl instanceof OtherRevocationInfoFormat,
            ),
        ).toBe(true)
    })

    test('can set custom content type', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .setContentType(OIDs.PKCS7.DATA)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .build()

        expect(signedData.encapContentInfo.eContentType.toString()).toBe(
            OIDs.PKCS7.DATA,
        )
    })

    test('can accept string data', async () => {
        const data = 'Plain text message'
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .build()

        expect(signedData).toBeInstanceOf(SignedData)

        const verified = await signedData.verify({
            data: new TextEncoder().encode(data),
        })
        expect(verified.valid).toBe(true)
    })

    test('can create signed data with multiple signers', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey1 = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate1 = Certificate.fromPem(rsaSigningKeys.certPem)
        const privateKey2 = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate2 = Certificate.fromPem(rsaSigningKeys.caCertPem)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey1,
                certificate: certificate1,
            })
            .addSigner({
                privateKeyInfo: privateKey2,
                certificate: certificate2,
            })
            .build()

        expect(signedData.signerInfos).toHaveLength(2)
    })

    test('throws error when no data is set', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)

        await expect(
            SignedData.builder()
                .addSigner({
                    privateKeyInfo: privateKey,
                    certificate,
                })
                .build(),
        ).rejects.toThrow('No data to sign')
    })

    test('creates SignedData even with no signers (empty signerInfos)', async () => {
        const data = new TextEncoder().encode('test')

        const signedData = await SignedData.builder().setData(data).build()

        expect(signedData).toBeInstanceOf(SignedData)
        expect(signedData.signerInfos).toHaveLength(0)
    })

    test('can create with both CRL and OCSP', async () => {
        const data = new TextEncoder().encode('test')
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const certificate = Certificate.fromPem(rsaSigningKeys.certPem)
        const crl = CertificateList.fromPem(rsaSigningKeys.caCrlPem)
        const ocspResponse = OCSPResponse.fromDer(rsaSigningKeys.ocspResponse)

        const signedData = await SignedData.builder()
            .setData(data)
            .addSigner({
                privateKeyInfo: privateKey,
                certificate,
            })
            .addCrl(crl)
            .addOcsp(ocspResponse)
            .build()

        expect(signedData.crls).toBeDefined()
        expect(signedData.crls!.length).toBeGreaterThanOrEqual(2)
    })
})
