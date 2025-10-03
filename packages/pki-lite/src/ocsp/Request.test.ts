import { describe, expect, it } from 'vitest'
import { Request } from './Request.js'
import { CertID } from './CertID.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { Extension } from '../x509/Extension.js'
import { asn1js } from '../core/PkiBase.js'

describe('Request', () => {
    const createTestCertID = () => {
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
        return new CertID({
            hashAlgorithm,
            issuerNameHash,
            issuerKeyHash,
            serialNumber,
        })
    }

    it('should create a Request with required fields only', () => {
        const certID = createTestCertID()
        const request = new Request({ reqCert: certID })

        expect(request.reqCert).toEqual(certID)
        expect(request.singleRequestExtensions).toBeUndefined()
    })

    it('should create a Request with extensions', () => {
        const certID = createTestCertID()
        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })
        const request = new Request({
            reqCert: certID,
            singleRequestExtensions: [extension],
        })

        expect(request.reqCert).toEqual(certID)
        expect(request.singleRequestExtensions).toHaveLength(1)
        expect(request.singleRequestExtensions?.[0]).toEqual(extension)
    })

    it('should create a Request with multiple extensions', () => {
        const certID = createTestCertID()
        const extension1 = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: new TextEncoder().encode('test1'),
        })
        const extension2 = new Extension({
            extnID: '1.2.3.5',
            critical: true,
            extnValue: new TextEncoder().encode('test2'),
        })
        const request = new Request({
            reqCert: certID,
            singleRequestExtensions: [extension1, extension2],
        })

        expect(request.reqCert).toEqual(certID)
        expect(request.singleRequestExtensions).toHaveLength(2)
        expect(request.singleRequestExtensions?.[0]).toEqual(extension1)
        expect(request.singleRequestExtensions?.[1]).toEqual(extension2)
    })

    it('should convert to ASN.1 and back without extensions', () => {
        const certID = createTestCertID()
        const original = new Request({ reqCert: certID })
        const asn1 = original.toAsn1()
        const parsed = Request.fromAsn1(asn1)

        expect(parsed.reqCert.hashAlgorithm.algorithm).toEqual(
            certID.hashAlgorithm.algorithm,
        )
        expect(parsed.singleRequestExtensions).toBeUndefined()
    })

    it('should convert to ASN.1 and back with extensions', () => {
        const certID = createTestCertID()
        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })
        const original = new Request({
            reqCert: certID,
            singleRequestExtensions: [extension],
        })
        const asn1 = original.toAsn1()
        const parsed = Request.fromAsn1(asn1)

        expect(parsed.reqCert.hashAlgorithm.algorithm).toEqual(
            certID.hashAlgorithm.algorithm,
        )
        expect(parsed.singleRequestExtensions).toHaveLength(1)
        expect(parsed.singleRequestExtensions?.[0].extnID.toString()).toEqual(
            '1.2.3.4',
        )
    })

    it('should convert to DER and back', () => {
        const certID = createTestCertID()
        const extensionValue = new TextEncoder().encode('test')
        const extension = new Extension({
            extnID: '1.2.3.4',
            critical: false,
            extnValue: extensionValue,
        })
        const original = new Request({
            reqCert: certID,
            singleRequestExtensions: [extension],
        })
        const der = original.toDer()
        const parsed = Request.fromDer(der)

        expect(parsed.reqCert.hashAlgorithm.algorithm).toEqual(
            certID.hashAlgorithm.algorithm,
        )
        expect(parsed.singleRequestExtensions).toHaveLength(1)
        expect(parsed.singleRequestExtensions?.[0].extnID.toString()).toEqual(
            '1.2.3.4',
        )
    })

    it('should throw error on invalid ASN.1 structure', () => {
        const invalidAsn1 = {} as any

        expect(() => Request.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error on wrong number of elements', () => {
        const invalidAsn1 = {
            constructor: asn1js.Sequence,
            valueBlock: {
                value: [1, 2, 3], // 3 elements instead of 1 or 2
            },
        } as any
        Object.setPrototypeOf(invalidAsn1, asn1js.Sequence.prototype)

        expect(() => Request.fromAsn1(invalidAsn1)).toThrow(
            'Invalid Request: expected 1 or 2 elements',
        )
    })

    it('should throw error on invalid extensions tag', () => {
        const certID = createTestCertID()
        const validCertIDAsn1 = certID.toAsn1()

        const invalidExtensionsContainer = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // CONTEXT-SPECIFIC
                tagNumber: 1, // [1] - wrong tag, should be [0]
            },
            value: [new asn1js.Sequence({ value: [] })],
        })

        const invalidAsn1 = new asn1js.Sequence({
            value: [validCertIDAsn1, invalidExtensionsContainer],
        })

        expect(() => Request.fromAsn1(invalidAsn1)).toThrow(
            'Invalid Request: expected [0] tag for singleRequestExtensions',
        )
    })

    it('should handle empty extensions array', () => {
        const certID = createTestCertID()
        const request = new Request({
            reqCert: certID,
            singleRequestExtensions: [],
        })

        expect(request.reqCert).toEqual(certID)
        expect(request.singleRequestExtensions).toEqual([])

        // When converting to ASN.1, empty extensions should not be included
        const asn1 = request.toAsn1()
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value).toHaveLength(1) // Only certID, no extensions
    })
})
