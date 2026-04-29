import { describe, expect, test } from 'vitest'
import { CertificateBuilder } from './CertificateBuilder.js'
import { Certificate } from '../../x509/Certificate.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { SubjectPublicKeyInfo } from '../../keys/SubjectPublicKeyInfo.js'
import { Extension } from '../../x509/Extension.js'
import { OIDs } from '../OIDs.js'
import { Name } from '../../x509/Name.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('CertificateBuilder', () => {
    test('can create a self-signed certificate', async () => {
        // Use pre-generated keys for testing
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const cert = await Certificate.builder()
            .setSubject('CN=Test Certificate, O=Test Org, C=US')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .selfSign()

        expect(cert).toBeInstanceOf(Certificate)
        expect(cert.tbsCertificate.subject).toBeDefined()
        expect(await cert.isSelfSigned()).toBe(true)
    })

    test('can create a CA-signed certificate', async () => {
        // Use pre-generated CA keys
        const caKeyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCaCert = Certificate.fromPem(rsaSigningKeys.caCertPem)
        const caPublicKey = loadedCaCert.tbsCertificate.subjectPublicKeyInfo

        // Create CA certificate
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA, O=Test Org, C=US')
            .setPublicKey(caPublicKey)
            .setPrivateKey(caKeyPair)
            .setValidityDays(3650)
            .selfSign()

        // Use pre-generated user keys
        const userKeyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedUserCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const userPublicKey = loadedUserCert.tbsCertificate.subjectPublicKeyInfo

        // Create user certificate signed by CA
        const userCert = await Certificate.builder()
            .setSubject('CN=Test User, O=Test Org, C=US')
            .setPublicKey(userPublicKey)
            .setIssuer(caCert)
            .setIssuerPrivateKey(caKeyPair)
            .setValidityDays(365)
            .sign()

        expect(userCert).toBeInstanceOf(Certificate)
        expect(userCert.tbsCertificate.subject).toBeDefined()
        expect(userCert.tbsCertificate.issuer).toBeDefined()
        expect(await userCert.isSelfSigned()).toBe(false)
    })

    test('can add extensions', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const basicConstraints = new Extension({
            extnID: OIDs.EXTENSION.BASIC_CONSTRAINTS,
            critical: true,
            extnValue: new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]), // CA:TRUE
        })

        const cert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .addExtension(basicConstraints)
            .selfSign()

        expect(cert.tbsCertificate.extensions).toBeDefined()
        expect(cert.tbsCertificate.extensions?.length).toBe(1)
        expect(cert.tbsCertificate.extensions?.[0].extnID.toString()).toBe(
            OIDs.EXTENSION.BASIC_CONSTRAINTS,
        )
    })

    test('can set validity period with dates', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const notBefore = new Date('2024-01-01T00:00:00Z')
        const notAfter = new Date('2025-01-01T00:00:00Z')

        const cert = await Certificate.builder()
            .setSubject('CN=Test')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityPeriod(notBefore, notAfter)
            .selfSign()

        expect(cert.tbsCertificate.validity.notBefore).toEqual(notBefore)
        expect(cert.tbsCertificate.validity.notAfter).toEqual(notAfter)
    })

    test('can generate serial number', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const cert = await Certificate.builder()
            .setSubject('CN=Test')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .generateSerialNumber()
            .selfSign()

        expect(cert.tbsCertificate.serialNumber).toBeDefined()
        expect(cert.tbsCertificate.serialNumber.bytes.length).toBe(20)
    })

    test('can set custom serial number', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const serialNumber = new Uint8Array([1, 2, 3, 4, 5])

        const cert = await Certificate.builder()
            .setSubject('CN=Test')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .setSerialNumber(serialNumber)
            .selfSign()

        expect(cert.tbsCertificate.serialNumber.bytes).toEqual(serialNumber)
    })

    test('can set algorithm', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const cert = await Certificate.builder()
            .setSubject('CN=Test')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .setAlgorithm({
                type: 'RSASSA_PKCS1_v1_5',
                params: { hash: 'SHA-512' },
            })
            .selfSign()

        expect(cert.signatureAlgorithm.algorithm.toString()).toBe(
            OIDs.RSA.SHA512_WITH_RSA,
        )
    })

    test('throws error when subject is missing', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        await expect(
            Certificate.builder()
                .setPublicKey(publicKey)
                .setPrivateKey(keyPair)
                .setValidityDays(365)
                .selfSign(),
        ).rejects.toThrow('Subject is required')
    })

    test('throws error when public key is missing', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)

        await expect(
            Certificate.builder()
                .setSubject('CN=Test')
                .setPrivateKey(keyPair)
                .setValidityDays(365)
                .selfSign(),
        ).rejects.toThrow('Public key is required')
    })

    test('throws error when private key is missing for self-signed', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        await expect(
            Certificate.builder()
                .setSubject('CN=Test')
                .setPublicKey(publicKey)
                .setValidityDays(365)
                .selfSign(),
        ).rejects.toThrow('Private key is required')
    })

    test('can use Name object for subject', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const subjectName = Name.parse('CN=Test Name, O=Test Org')

        const cert = await Certificate.builder()
            .setSubject(subjectName)
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .selfSign()

        expect(cert.tbsCertificate.subject).toBe(subjectName)
    })

    test('build() method creates self-signed cert when no issuer', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const cert = await Certificate.builder()
            .setSubject('CN=Test')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .build()

        expect(await cert.isSelfSigned()).toBe(true)
    })

    test('can add multiple extensions', async () => {
        const keyPair = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const loadedCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = loadedCert.tbsCertificate.subjectPublicKeyInfo

        const ext1 = new Extension({
            extnID: OIDs.EXTENSION.BASIC_CONSTRAINTS,
            critical: true,
            extnValue: new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]),
        })

        const ext2 = new Extension({
            extnID: OIDs.EXTENSION.KEY_USAGE,
            critical: true,
            extnValue: new Uint8Array([0x03, 0x02, 0x05, 0xa0]),
        })

        const cert = await Certificate.builder()
            .setSubject('CN=Test')
            .setPublicKey(publicKey)
            .setPrivateKey(keyPair)
            .setValidityDays(365)
            .addExtensions(ext1, ext2)
            .selfSign()

        expect(cert.tbsCertificate.extensions?.length).toBe(2)
    })
})
