import { describe, expect, it } from 'vitest'
import { BasicOCSPResponse } from './BasicOCSPResponse.js'
import { ResponseData } from './ResponseData.js'
import { SingleResponse } from './SingleResponse.js'
import { CertStatus } from './CertStatus.js'
import { CertID } from './CertID.js'
import { ResponderID } from './ResponderID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { beforeAll } from 'vitest'
import { Certificate } from '../x509/Certificate.js'
import { ocspTestPki } from '../../test-fixtures/ocsp.js'

describe('BasicOCSPResponse', () => {
    it('should create a BasicOCSPResponse with minimum fields', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({ bytes: new Uint8Array([123]) })
        const issuerKeyHash = new OctetString({ bytes: new Uint8Array([123]) })
        const serialNumber = new Uint8Array([9, 10, 11, 12])
        const certID = new CertID({
            hashAlgorithm: hashAlgorithm,
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumber: serialNumber,
        })

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID: certID,
            certStatus: certStatus,
            thisUpdate: thisUpdate,
        })

        const keyHash = new OctetString({ bytes: new Uint8Array([1, 2, 3, 4]) })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()
        const responseData = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
        })

        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA-256 with RSA
        const signatureValue = new Uint8Array([1, 2, 3, 4, 5])

        const basicResponse = new BasicOCSPResponse({
            tbsResponseData: responseData,
            signatureAlgorithm,
            signature: signatureValue,
        })

        expect(basicResponse.tbsResponseData).toEqual(responseData)
        expect(basicResponse.signatureAlgorithm).toEqual(signatureAlgorithm)
        expect(basicResponse.signature.bytes).toEqual(signatureValue)
        expect(basicResponse.certs).toBeUndefined()
    })

    // Skip certificate test because we need a proper certificate implementation

    it('should convert to ASN.1 and back', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new OctetString({
            bytes: new Uint8Array([1, 2, 3, 4]),
        })
        const issuerKeyHash = new OctetString({
            bytes: new Uint8Array([5, 6, 7, 8]),
        })
        const serialNumber = new Uint8Array([9, 10, 11, 12])
        const certID = new CertID({
            hashAlgorithm: hashAlgorithm,
            issuerNameHash: issuerNameHash,
            issuerKeyHash: issuerKeyHash,
            serialNumber: serialNumber,
        })

        const certStatus = CertStatus.createGood()
        const thisUpdate = new Date()
        const singleResponse = new SingleResponse({
            certID: certID,
            certStatus: certStatus,
            thisUpdate: thisUpdate,
        })

        const keyHash = new OctetString({ bytes: new Uint8Array([1, 2, 3, 4]) })
        const responderID = new ResponderID.byKey(keyHash)

        const producedAt = new Date()
        const responseData = new ResponseData({
            responses: [singleResponse],
            responderID,
            producedAt,
        })

        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA-256 with RSA
        const signatureValue = new Uint8Array([1, 2, 3, 4, 5])

        const original = new BasicOCSPResponse({
            tbsResponseData: responseData,
            signatureAlgorithm,
            signature: signatureValue,
        })
        const asn1 = original.toAsn1()
        const parsed = BasicOCSPResponse.fromAsn1(asn1)

        expect(parsed.tbsResponseData.version).toEqual(0) // v1
        expect(parsed.tbsResponseData.responderID).toBeInstanceOf(
            ResponderID.byKey,
        )
        expect(parsed.signatureAlgorithm.algorithm).toEqual(
            signatureAlgorithm.algorithm,
        )
        expect(parsed.signature.bytes).toEqual(signatureValue)
        expect(parsed.certs).toBeUndefined()
    })
})

describe('BasicOCSPResponse.verify (RFC 6960 4.2.2.2)', () => {
    let pki: Awaited<ReturnType<typeof ocspTestPki>>
    beforeAll(async () => {
        pki = await ocspTestPki()
    })
    const basic = async (options: Parameters<typeof pki.respond>[0]) =>
        (await pki.respond(options)).getBasicOCSPResponse()

    it('accepts a response signed by the CA', async () => {
        const response = await basic({ signer: pki.ca, key: pki.caKey })
        expect(await response.verify(pki.ca)).toBe(true)
    })

    it('accepts a delegated responder with OCSPSigning, issued by the CA', async () => {
        const response = await basic({
            signer: pki.responder,
            key: pki.otherKey,
            include: [pki.responder],
        })
        expect(await response.verify(pki.ca)).toBe(true)
    })

    it('rejects a delegated responder that is not in the response', async () => {
        const response = await basic({
            signer: pki.responder,
            key: pki.otherKey,
        })
        expect(await response.verify(pki.ca)).toBe(false)
    })

    it('rejects a certificate of the CA without OCSPSigning', async () => {
        const response = await basic({
            signer: pki.notResponder,
            key: pki.otherKey,
            include: [pki.notResponder],
        })
        expect(await response.verify(pki.ca)).toBe(false)
    })

    it('rejects a delegated responder outside its validity period', async () => {
        const response = await basic({
            signer: pki.expiredResponder,
            key: pki.otherKey,
            include: [pki.expiredResponder],
        })
        expect(await response.verify(pki.ca)).toBe(false)
        expect(
            await response.verify(pki.ca, {
                time: new Date('2024-06-01T00:00:00Z'),
            }),
        ).toBe(true)
    })

    it('rejects a response signed by another key under the CA name', async () => {
        const response = await basic({
            signer: pki.impostorCa,
            key: pki.otherKey,
        })
        expect(await response.verify(pki.ca)).toBe(false)
    })

    it('rejects an OCSPSigning responder issued by another CA', async () => {
        const rogue = await Certificate.builder()
            .setSubject('CN=Rogue Responder')
            .setPublicKey(pki.responder.tbsCertificate.subjectPublicKeyInfo)
            .setIssuer(pki.impostorCa)
            .setIssuerPrivateKey(pki.otherKey)
            .setSerialNumber(66)
            .setValidityPeriod(new Date('2024-01-01'), new Date('2034-01-01'))
            .addExtendedKeyUsage({ ocspSigning: true })
            .sign()
        const response = await basic({
            signer: rogue,
            key: pki.otherKey,
            include: [rogue],
        })
        expect(await response.verify(pki.ca)).toBe(false)
    })

    it('rejects a response whose responderID does not name its signer', async () => {
        // signed with the CA's key, but naming the delegated responder
        const response = await basic({
            signer: pki.responder,
            key: pki.caKey,
            include: [pki.responder],
        })
        expect(await response.verify(pki.ca)).toBe(false)
    })

    it('rejects a response whose data was changed after signing', async () => {
        const response = await basic({ signer: pki.ca, key: pki.caKey })
        response.tbsResponseData.producedAt = new Date('2020-01-01T00:00:00Z')
        expect(await response.verify(pki.ca)).toBe(false)
    })
})
