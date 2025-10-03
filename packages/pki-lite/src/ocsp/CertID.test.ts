import { describe, expect, it } from 'vitest'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { asn1js } from '../core/PkiBase.js'

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
})
