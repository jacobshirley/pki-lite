import { describe, it, expect } from 'vitest'
import { OCSPRequest } from '../../ocsp/OCSPRequest.js'
import { Certificate } from '../../x509/Certificate.js'
import { rsaSigningKeys } from '../../../test-fixtures/signing-keys/rsa-2048/index.js'
import { KeyGen } from '../KeyGen.js'
import { Request } from '../../ocsp/Request.js'
import { CertID } from '../../ocsp/CertID.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { PrivateKeyInfo } from '../../keys/PrivateKeyInfo.js'

describe('OCSPRequestBuilder', () => {
    it('builds a basic OCSP request for a single certificate', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create a user certificate
        const userKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caPrivateKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )
        const userCert = await Certificate.builder()
            .setSubject('CN=user@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(userKeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const request = await OCSPRequest.builder()
            .addCertificate({
                certificate: userCert,
                issuerCertificate: caCert,
            })
            .build()

        expect(request).toBeInstanceOf(OCSPRequest)
        expect(request.tbsRequest.requestList).toBeDefined()
        expect(request.tbsRequest.requestList.length).toBe(1)

        // Round-trip
        const der = request.toDer()
        const decoded = OCSPRequest.fromDer(der)
        expect(decoded.toDer()).toEqual(request.toDer())
    })

    it('builds an OCSP request for multiple certificates', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)

        // Create two user certificates
        const user1KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caPrivateKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )
        const user1Cert = await Certificate.builder()
            .setSubject('CN=user1@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(user1KeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const user2KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const user2Cert = await Certificate.builder()
            .setSubject('CN=user2@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(user2KeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const request = await OCSPRequest.builder()
            .addCertificate({
                certificate: user1Cert,
                issuerCertificate: caCert,
            })
            .addCertificate({
                certificate: user2Cert,
                issuerCertificate: caCert,
            })
            .build()

        expect(request).toBeInstanceOf(OCSPRequest)
        expect(request.tbsRequest.requestList.length).toBe(2)
    })

    it('builds an OCSP request with SHA-1 hash algorithm', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)

        const userKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caPrivateKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )
        const userCert = await Certificate.builder()
            .setSubject('CN=user@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(userKeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const request = await OCSPRequest.builder()
            .setHashAlgorithm('SHA-1')
            .addCertificate({
                certificate: userCert,
                issuerCertificate: caCert,
            })
            .build()

        expect(request).toBeInstanceOf(OCSPRequest)
        expect(request.tbsRequest.requestList).toBeDefined()

        // Verify the hash algorithm in CertID is SHA-1
        const certID = request.tbsRequest.requestList[0].reqCert
        expect(certID.hashAlgorithm.algorithm.toString()).toBe(
            '1.3.14.3.2.26', // SHA-1
        )
    })

    it('builds an OCSP request with requestor name', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)

        const userKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caPrivateKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )
        const userCert = await Certificate.builder()
            .setSubject('CN=user@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(userKeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const request = await OCSPRequest.builder()
            .setRequestorName('CN=OCSP Client, O=Example Org')
            .addCertificate({
                certificate: userCert,
                issuerCertificate: caCert,
            })
            .build()

        expect(request).toBeInstanceOf(OCSPRequest)
        expect(request.tbsRequest.requestorName).toBeDefined()
    })

    it('builds an OCSP request with pre-built Request', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)
        const hashAlgorithm = AlgorithmIdentifier.digestAlgorithm('SHA-256')

        const certID = new CertID({
            hashAlgorithm,
            issuerNameHash: await hashAlgorithm.digest(
                caCert.tbsCertificate.subject.toDer(),
            ),
            issuerKeyHash: await hashAlgorithm.digest(
                caCert.getSubjectPublicKeyInfo().subjectPublicKey,
            ),
            serialNumber: 12345,
        })

        const prebuiltRequest = new Request({ reqCert: certID })

        const request = await OCSPRequest.builder()
            .addRequest(prebuiltRequest)
            .build()

        expect(request).toBeInstanceOf(OCSPRequest)
        expect(request.tbsRequest.requestList.length).toBe(1)
    })

    it('builds an OCSP request with extensions', async () => {
        const caCert = Certificate.fromPem(rsaSigningKeys.certPem)

        const userKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caPrivateKey = PrivateKeyInfo.fromPem(
            rsaSigningKeys.privateKeyPem,
        )
        const userCert = await Certificate.builder()
            .setSubject('CN=user@example.com')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(userKeyPair.publicKey)
            .setPrivateKey(caPrivateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        // Create a nonce extension for replay protection
        const nonce = crypto.getRandomValues(new Uint8Array(16))
        const nonceExt = {
            extnID: '1.3.6.1.5.5.7.48.1.2', // OCSP Nonce OID
            extnValue: nonce,
        }

        const request = await OCSPRequest.builder()
            .addCertificate({
                certificate: userCert,
                issuerCertificate: caCert,
            })
            .addExtension(nonceExt as any)
            .build()

        expect(request).toBeInstanceOf(OCSPRequest)
        expect(request.tbsRequest.requestExtensions).toBeDefined()
    })
})
