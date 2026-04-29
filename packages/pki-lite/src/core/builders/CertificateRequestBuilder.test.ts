import { describe, it, expect } from 'vitest'
import { CertificateRequest } from '../../x509/CertificateRequest.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'
import { Certificate } from '../../x509/Certificate.js'
import { KeyGen } from '../KeyGen.js'

describe('CertificateRequestBuilder', () => {
    it('builds a basic CSR and round-trips', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = cert.tbsCertificate.subjectPublicKeyInfo

        const csr = await CertificateRequest.builder()
            .setSubject('CN=example.com, O=Example Org, C=US')
            .setPublicKey(publicKey)
            .setPrivateKey(privateKey)
            .build()

        expect(csr).toBeInstanceOf(CertificateRequest)
        const subjectStr = csr.requestInfo.subject.toString()
        expect(subjectStr).toContain('example.com')

        // Round-trip
        const der = csr.toDer()
        const decoded = CertificateRequest.fromDer(der)
        expect(decoded.toDer()).toEqual(csr.toDer())
    })

    it('builds a CSR with key usage extension', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = cert.tbsCertificate.subjectPublicKeyInfo

        const csr = await CertificateRequest.builder()
            .setSubject('CN=server.example.com')
            .setPublicKey(publicKey)
            .setPrivateKey(privateKey)
            .addKeyUsage({
                digitalSignature: true,
                keyEncipherment: true,
            })
            .build()

        expect(csr).toBeInstanceOf(CertificateRequest)

        // Verify extension request attribute is present
        const attributes = csr.requestInfo.attributes
        expect(attributes).toBeDefined()
        expect(attributes!.length).toBeGreaterThan(0)
    })

    it('builds a CSR with subject alternative names', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = cert.tbsCertificate.subjectPublicKeyInfo

        const csr = await CertificateRequest.builder()
            .setSubject('CN=api.example.com')
            .setPublicKey(publicKey)
            .setPrivateKey(privateKey)
            .addSubjectAltName('api.example.com', '*.api.example.com')
            .build()

        expect(csr).toBeInstanceOf(CertificateRequest)

        // Verify attributes exist
        const attributes = csr.requestInfo.attributes
        expect(attributes).toBeDefined()
        expect(attributes!.length).toBeGreaterThan(0)
    })

    it('builds a CSR with extended key usage', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = cert.tbsCertificate.subjectPublicKeyInfo

        const csr = await CertificateRequest.builder()
            .setSubject('CN=server.example.com')
            .setPublicKey(publicKey)
            .setPrivateKey(privateKey)
            .addExtendedKeyUsage({
                serverAuth: true,
                clientAuth: true,
            })
            .build()

        expect(csr).toBeInstanceOf(CertificateRequest)

        const attributes = csr.requestInfo.attributes
        expect(attributes).toBeDefined()
    })

    it('builds a CSR with multiple extensions', async () => {
        const privateKey = PrivateKeyInfo.fromPem(rsaSigningKeys.privateKeyPem)
        const cert = Certificate.fromPem(rsaSigningKeys.certPem)
        const publicKey = cert.tbsCertificate.subjectPublicKeyInfo

        const csr = await CertificateRequest.builder()
            .setSubject('CN=multi.example.com, O=Example Corp, C=US')
            .setPublicKey(publicKey)
            .setPrivateKey(privateKey)
            .addKeyUsage({
                digitalSignature: true,
                keyEncipherment: true,
            })
            .addExtendedKeyUsage({
                serverAuth: true,
            })
            .addSubjectAltName('multi.example.com', 'www.multi.example.com')
            .build()

        expect(csr).toBeInstanceOf(CertificateRequest)
        expect(csr.requestInfo.attributes!.length).toBeGreaterThan(0)
    })

    it('builds a CSR with custom signature algorithm', async () => {
        const keyPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })

        const csr = await CertificateRequest.builder()
            .setSubject('CN=ec-test.example.com')
            .setPublicKey(keyPair.publicKey)
            .setPrivateKey(keyPair.privateKey)
            .setAlgorithm({
                type: 'ECDSA',
                params: { namedCurve: 'P-256', hash: 'SHA-256' },
            })
            .build()

        expect(csr).toBeInstanceOf(CertificateRequest)
        expect(csr.signatureAlgorithm.algorithm.toString()).toContain(
            '1.2.840.10045.4.3.2',
        ) // ecdsa-with-SHA256
    })
})
