import { describe, expect, test } from 'vitest'
import { OCSPResponse } from '../../src/ocsp/OCSPResponse.js'
import { OCSPResponseStatus } from '../../src/ocsp/OCSPResponseStatus.js'
import { CertID } from '../../src/ocsp/CertID.js'
import { Certificate } from '../../src/x509/Certificate.js'
import { KeyGen } from '../../src/core/KeyGen.js'
import { AlgorithmIdentifier } from '../../src/algorithms/AlgorithmIdentifier.js'

describe('OCSPResponseBuilder', () => {
    test('can build a basic OCSP response with good status', async () => {
        // Setup: Create CA and certificates
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addExtendedKeyUsage({ ocspSigning: true })
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=User Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(12345)
            .build()

        // Build OCSP response
        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert, 'good')
            .build()

        expect(response.responseStatus.value).toBe(0)
        expect(response.responseBytes).toBeDefined()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.responses).toHaveLength(1)
        expect(basicResp.tbsResponseData.responses[0].certStatus.status).toBe(
            'good',
        )
    })

    test('can build OCSP response with revoked status', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=Revoked Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(54321)
            .build()

        const revocationDate = new Date('2024-01-01')

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert, 'revoked', {
                revocationTime: revocationDate,
                revocationReason: 0,
            })
            .build()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.responses[0].certStatus.status).toBe(
            'revoked',
        )
        expect(
            basicResp.tbsResponseData.responses[0].certStatus.revocationTime,
        ).toEqual(revocationDate)
        expect(
            basicResp.tbsResponseData.responses[0].certStatus.revocationReason,
        ).toBe(0)
    })

    test('can build OCSP response with multiple certificate statuses', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert1 = await Certificate.builder()
            .setSubject('CN=Good Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(100)
            .build()

        const cert2 = await Certificate.builder()
            .setSubject('CN=Revoked Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(200)
            .build()

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert1, 'good')
            .addResponse(caCert, cert2, 'revoked', {
                revocationTime: new Date('2024-01-01'),
                revocationReason: 1,
            })
            .build()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.responses).toHaveLength(2)
        expect(basicResp.tbsResponseData.responses[0].certStatus.status).toBe(
            'good',
        )
        expect(basicResp.tbsResponseData.responses[1].certStatus.status).toBe(
            'revoked',
        )
    })

    test('can build OCSP response with CertID directly', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=User Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(12345)
            .build()

        // Create CertID manually
        const certID = await CertID.forCertificate(caCert, cert)

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(certID, 'good')
            .build()

        expect(response.responseStatus.value).toBe(0)
        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.responses).toHaveLength(1)
    })

    test('can build OCSP response with custom validity period', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=User Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(12345)
            .build()

        const now = new Date()
        const thisUpdate = new Date(now.getTime() + 24 * 60 * 60 * 1000)
        const nextUpdate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000)

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .setProducedAt(now)
            .addResponse(caCert, cert, 'good', {
                thisUpdate,
                nextUpdate,
            })
            .build()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.producedAt.getTime()).toBe(
            now.getTime(),
        )
        expect(
            basicResp.tbsResponseData.responses[0].thisUpdate.time.getTime(),
        ).toBe(thisUpdate.getTime())
        expect(
            basicResp.tbsResponseData.responses[0].nextUpdate?.time.getTime(),
        ).toBe(nextUpdate.getTime())
    })

    test('can build OCSP response with included certificates', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=User Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(12345)
            .build()

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert, 'good')
            .addCertificate(responderCert)
            .build()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.certs).toBeDefined()
        expect(basicResp.certs).toHaveLength(1)
        expect(basicResp.certs![0].tbsCertificate.subject.toString()).toBe(
            responderCert.tbsCertificate.subject.toString(),
        )
    })

    test('can build error response without responder info', async () => {
        const response = await OCSPResponse.builder()
            .setResponseStatus(OCSPResponseStatus.malformedRequest)
            .build()

        expect(response.responseStatus.value).toBe(1)
        expect(response.responseBytes).toBeUndefined()
    })

    test('can use setResponderByName', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=User Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(12345)
            .build()

        const response = await OCSPResponse.builder()
            .setResponderByName('CN=OCSP Responder')
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert, 'good')
            .build()

        expect(response.responseStatus.value).toBe(0)
    })

    test('can build response with unknown status', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=Unknown Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(99999)
            .build()

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert, 'unknown')
            .build()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.responses[0].certStatus.status).toBe(
            'unknown',
        )
    })

    test('can serialize and deserialize OCSP response', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        const cert = await Certificate.builder()
            .setSubject('CN=User Cert')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(12345)
            .build()

        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(caCert, cert, 'good')
            .build()

        const der = response.toDer()
        const parsed = OCSPResponse.fromDer(der)

        expect(parsed.responseStatus.value).toBe(response.responseStatus.value)
        expect(parsed.responseBytes?.responseType).toBe(
            response.responseBytes?.responseType,
        )
    })

    test('throws error when building without required fields', async () => {
        await expect(OCSPResponse.builder().build()).rejects.toThrow(
            'Responder ID is required',
        )
    })

    test('throws error when issuer certificate not set for Certificate objects', async () => {
        const caKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const caCert = await Certificate.builder()
            .setSubject('CN=Test CA')
            .setPublicKey(caKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(caCert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(caKeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        await expect(
            OCSPResponse.builder()
                .setResponderFromCertificate(responderCert)
                .setPrivateKey(responderKeyPair.privateKey)
                .build(),
        ).rejects.toThrow('At least one certificate response is required')
    })

    test('supports different issuers for different certificates', async () => {
        // Create two different CAs
        const ca1KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const ca1Cert = await Certificate.builder()
            .setSubject('CN=CA 1')
            .setPublicKey(ca1KeyPair.publicKey)
            .setPrivateKey(ca1KeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const ca2KeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const ca2Cert = await Certificate.builder()
            .setSubject('CN=CA 2')
            .setPublicKey(ca2KeyPair.publicKey)
            .setPrivateKey(ca2KeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .addBasicConstraints(true)
            .selfSign()

        const responderKeyPair = await KeyGen.generateRsaPair({ keySize: 2048 })
        const responderCert = await Certificate.builder()
            .setSubject('CN=OCSP Responder')
            .setIssuer(ca1Cert.tbsCertificate.subject)
            .setPublicKey(responderKeyPair.publicKey)
            .setPrivateKey(ca1KeyPair.privateKey)
            .setValidityDays(365)
            .generateSerialNumber()
            .build()

        // Create certs from different CAs
        const cert1 = await Certificate.builder()
            .setSubject('CN=Cert from CA1')
            .setIssuer(ca1Cert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(ca1KeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(100)
            .build()

        const cert2 = await Certificate.builder()
            .setSubject('CN=Cert from CA2')
            .setIssuer(ca2Cert.tbsCertificate.subject)
            .setPublicKey(
                (await KeyGen.generateRsaPair({ keySize: 2048 })).publicKey,
            )
            .setPrivateKey(ca2KeyPair.privateKey)
            .setValidityDays(365)
            .setSerialNumber(200)
            .build()

        // Build response with certificates from different issuers
        const response = await OCSPResponse.builder()
            .setResponderFromCertificate(responderCert)
            .setPrivateKey(responderKeyPair.privateKey)
            .addResponse(ca1Cert, cert1, 'good')
            .addResponse(ca2Cert, cert2, 'good')
            .build()

        const basicResp = response.getBasicOCSPResponse()
        expect(basicResp.tbsResponseData.responses).toHaveLength(2)
        expect(basicResp.tbsResponseData.responses[0].certStatus.status).toBe(
            'good',
        )
        expect(basicResp.tbsResponseData.responses[1].certStatus.status).toBe(
            'good',
        )
    })
})
