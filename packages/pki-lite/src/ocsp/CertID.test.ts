import { describe, expect, it } from 'vitest'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { asn1js } from '../core/PkiBase.js'
import { Certificate } from '../x509/Certificate.js'
import { rsaSigningKeys } from '../../test-fixtures/signing-keys/rsa-2048/index.js'

describe('CertID', () => {
    it('should create a CertID with all fields', () => {
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
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })

        expect(certID.hashAlgorithm).toEqual(hashAlgorithm)
        expect(certID.issuerNameHash).toEqual(issuerNameHash)
        expect(certID.issuerKeyHash).toEqual(issuerKeyHash)
        expect(certID.serialNumber.bytes).toEqual(serialNumber)
    })

    it('should create a CertID with Uint8Array<ArrayBuffer> hash values', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = new Uint8Array([1, 2, 3, 4])
        const issuerKeyHash = new Uint8Array([5, 6, 7, 8])
        const serialNumber = new Uint8Array([9, 10, 11, 12])

        const certID = new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })

        expect(certID.hashAlgorithm).toEqual(hashAlgorithm)
        expect(certID.issuerNameHash).toBeInstanceOf(OctetString)
        expect(certID.issuerKeyHash).toBeInstanceOf(OctetString)
        expect(certID.issuerNameHash.bytes).toEqual(issuerNameHash)
        expect(certID.issuerKeyHash.bytes).toEqual(issuerKeyHash)
        expect(certID.serialNumber.bytes).toEqual(serialNumber)
    })

    it('should create a CertID with string hash values', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const issuerNameHash = 'test name hash'
        const issuerKeyHash = 'test key hash'
        const serialNumber = new Uint8Array([9, 10, 11, 12])

        const certID = new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })

        expect(certID.hashAlgorithm).toEqual(hashAlgorithm)
        expect(certID.issuerNameHash).toBeInstanceOf(OctetString)
        expect(certID.issuerKeyHash).toBeInstanceOf(OctetString)
        expect(certID.serialNumber.bytes).toEqual(serialNumber)
    })

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

        const original = new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })
        const asn1 = original.toAsn1()
        const parsed = CertID.fromAsn1(asn1)

        expect(parsed.hashAlgorithm.algorithm).toEqual(hashAlgorithm.algorithm)
        expect(parsed.issuerNameHash.bytes).toEqual(issuerNameHash.bytes)
        expect(parsed.issuerKeyHash.bytes).toEqual(issuerKeyHash.bytes)
        expect(parsed.serialNumber.bytes).toEqual(serialNumber)
    })

    it('should convert to DER and back', () => {
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

        const original = new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })
        const der = original.toDer()
        const parsed = CertID.fromDer(der)

        expect(parsed.hashAlgorithm.algorithm).toEqual(hashAlgorithm.algorithm)
        expect(parsed.issuerNameHash.bytes).toEqual(issuerNameHash.bytes)
        expect(parsed.issuerKeyHash.bytes).toEqual(issuerKeyHash.bytes)
        expect(parsed.serialNumber.bytes).toEqual(serialNumber)
    })

    it('keeps a negative serial number negative when parsed', () => {
        const original = new CertID({
            hashAlgorithm: new AlgorithmIdentifier({
                algorithm: '2.16.840.1.101.3.4.2.1',
            }),
            issuerNameHash: new OctetString({ bytes: new Uint8Array([1]) }),
            issuerKeyHash: new OctetString({ bytes: new Uint8Array([2]) }),
            serialNumber: -1n,
        })

        const parsed = CertID.fromDer(original.toDer())
        expect(parsed.serialNumber.toBigInt()).toBe(-1n)
        expect(parsed.toDer()).toEqual(original.toDer())
    })

    it('should throw error on invalid ASN.1 structure', () => {
        const invalidAsn1 = {} as any

        expect(() => CertID.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error on wrong number of elements', () => {
        const invalidAsn1 = {
            constructor: asn1js.Sequence,
            valueBlock: {
                value: [1, 2], // only 2 elements instead of 4
            },
        } as any
        // Make it instanceof asn1js.Sequence by setting prototype
        Object.setPrototypeOf(invalidAsn1, asn1js.Sequence.prototype)

        expect(() => CertID.fromAsn1(invalidAsn1)).toThrow(
            'Invalid CertID: expected 4 elements',
        )
    })

    it('forCertificate hashes the issuer name and key bits (RFC 6960 4.1.1)', async () => {
        const issuer = Certificate.fromPem(rsaSigningKeys.caCertPem)
        const subject = Certificate.fromPem(rsaSigningKeys.certPem)
        const sha1 = async (bytes: Uint8Array<ArrayBuffer>) =>
            new Uint8Array(await crypto.subtle.digest('SHA-1', bytes))

        const certID = await CertID.forCertificate(
            issuer,
            subject,
            AlgorithmIdentifier.digestAlgorithm('SHA-1'),
        )

        expect(certID.issuerNameHash.bytes).toEqual(
            await sha1(issuer.tbsCertificate.subject.toDer()),
        )
        // the key bits only: not the BIT STRING's tag, length and unused-bits octet
        expect(certID.issuerKeyHash.bytes).toEqual(
            await sha1(
                issuer.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
                    .bytes,
            ),
        )
        expect(
            certID.serialNumber.equals(subject.tbsCertificate.serialNumber),
        ).toBe(true)
    })
})

describe('CertID.matches', () => {
    it('matches the certificate from its issuer only', async () => {
        const issuer = Certificate.fromPem(rsaSigningKeys.caCertPem)
        const subject = Certificate.fromPem(rsaSigningKeys.certPem)
        for (const hash of ['SHA-1', 'SHA-256'] as const) {
            const certID = await CertID.forCertificate(
                issuer,
                subject,
                AlgorithmIdentifier.digestAlgorithm(hash),
            )
            expect(await certID.matches(subject, issuer)).toBe(true)
            // another issuer: different name and key hashes
            expect(await certID.matches(subject, subject)).toBe(false)
        }
        const certID = await CertID.forCertificate(issuer, subject)
        // another certificate: different serial number
        expect(await certID.matches(issuer, issuer)).toBe(false)
    })
})
