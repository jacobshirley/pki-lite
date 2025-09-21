import { describe, expect, it } from 'vitest'
import { OCSPSignature } from './OCSPSignature.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../x509/Certificate.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { Validity } from '../x509/Validity.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'

describe('OCSPSignature', () => {
    const createTestAlgorithm = () => {
        return new AlgorithmIdentifier({ algorithm: '1.2.840.113549.1.1.11' }) // SHA-256 with RSA
    }

    const createTestSignature = () => {
        return new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    }

    const createTestCertificate = (): Certificate => {
        // Create a simple name
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Certificate',
        })
        const cnRdn = new RelativeDistinguishedName()
        cnRdn.push(cn)
        const name = new Name.RDNSequence()
        name.push(cnRdn)

        // Create a sample key
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])
        const spki = new SubjectPublicKeyInfo({
            algorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.1',
            }),
            subjectPublicKey: publicKey,
        })

        const validity = new Validity({
            notBefore: new Date('2025-01-01'),
            notAfter: new Date('2026-01-01'),
        })

        const serialNumber = 1234567890

        // Create a basic TBSCertificate

        const tbsCertificate = new Certificate.TBSCertificate({
            version: 2,
            serialNumber: serialNumber, // X.509v3
            signature: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }),
            issuer: name,
            validity: validity,
            subject: name,
            subjectPublicKeyInfo: spki,
        })

        const signatureValue = new Uint8Array([10, 20, 30, 40, 50])

        return new Certificate({
            tbsCertificate: tbsCertificate,
            signatureAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.2.840.113549.1.1.11',
            }),
            signatureValue: signatureValue,
        })
    }

    it('should create an OCSPSignature with required fields only', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm,
            signature,
        })

        expect(ocspSignature.signatureAlgorithm).toBe(signatureAlgorithm)
        expect(ocspSignature.signature).toBe(signature)
        expect(ocspSignature.certs).toBeUndefined()
    })

    it('should create an OCSPSignature with certificates', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()

        const cert = createTestCertificate()
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm,
            signature,
            certs: [cert],
        })

        expect(ocspSignature.signatureAlgorithm).toBe(signatureAlgorithm)
        expect(ocspSignature.signature).toBe(signature)
        expect(ocspSignature.certs).toHaveLength(1)
        expect(ocspSignature.certs?.[0]).toBe(cert)
    })

    it('should create an OCSPSignature with multiple certificates', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()

        const cert1 = createTestCertificate()
        const cert2 = createTestCertificate()
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm,
            signature,
            certs: [cert1, cert2],
        })

        expect(ocspSignature.signatureAlgorithm).toBe(signatureAlgorithm)
        expect(ocspSignature.signature).toBe(signature)
        expect(ocspSignature.certs).toHaveLength(2)
        expect(ocspSignature.certs?.[0]).toBe(cert1)
        expect(ocspSignature.certs?.[1]).toBe(cert2)
    })

    it('should convert to ASN.1 and back without certificates', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()
        const original = new OCSPSignature({ signatureAlgorithm, signature })

        const asn1 = original.toAsn1()
        const parsed = OCSPSignature.fromAsn1(asn1)

        expect(parsed.signatureAlgorithm.algorithm).toEqual(
            signatureAlgorithm.algorithm,
        )
        expect(parsed.signature).toEqual(signature)
        expect(parsed.certs).toBeUndefined()
    })

    it('should convert to ASN.1 and back with certificates', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()
        const cert = createTestCertificate()
        const original = new OCSPSignature({
            signatureAlgorithm,
            signature,
            certs: [cert],
        })

        const asn1 = original.toAsn1()
        const parsed = OCSPSignature.fromAsn1(asn1)

        expect(parsed.signatureAlgorithm.algorithm).toEqual(
            signatureAlgorithm.algorithm,
        )
        expect(parsed.signature).toEqual(signature)
        expect(parsed.certs).toHaveLength(1)
    })

    it('should convert to DER and back', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()
        const original = new OCSPSignature({ signatureAlgorithm, signature })

        const der = original.toDer()
        const parsed = OCSPSignature.fromDer(der)

        expect(parsed.signatureAlgorithm.algorithm).toEqual(
            signatureAlgorithm.algorithm,
        )
        expect(parsed.signature).toEqual(signature)
        expect(parsed.certs).toBeUndefined()
    })

    it('should throw error on invalid ASN.1 structure', () => {
        const invalidAsn1 = {} as any

        expect(() => OCSPSignature.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error on wrong number of elements', () => {
        const invalidAsn1 = {
            constructor: asn1js.Sequence,
            valueBlock: {
                value: [1], // only 1 element instead of 2 or 3
            },
        } as any
        Object.setPrototypeOf(invalidAsn1, asn1js.Sequence.prototype)

        expect(() => OCSPSignature.fromAsn1(invalidAsn1)).toThrow(
            'Invalid Signature: expected 2 or 3 elements',
        )
    })

    it('should throw error on invalid certs tag', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()
        const validAlgorithmAsn1 = signatureAlgorithm.toAsn1()
        const validSignatureAsn1 = new asn1js.BitString({ valueHex: signature })

        const invalidCertsContainer = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // CONTEXT-SPECIFIC
                tagNumber: 1, // [1] - wrong tag, should be [0]
            },
            value: [new asn1js.Sequence({ value: [] })],
        })

        const invalidAsn1 = new asn1js.Sequence({
            value: [
                validAlgorithmAsn1,
                validSignatureAsn1,
                invalidCertsContainer,
            ],
        })

        expect(() => OCSPSignature.fromAsn1(invalidAsn1)).toThrow(
            'Invalid Signature: expected [0] tag for certs',
        )
    })

    it('should handle empty certs array', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const signature = createTestSignature()
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm,
            signature,
            certs: [],
        })

        expect(ocspSignature.certs).toEqual([])

        // When converting to ASN.1, empty certs should not be included
        const asn1 = ocspSignature.toAsn1()
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value).toHaveLength(2) // Only algorithm and signature
    })

    it('should handle large signature values', () => {
        const signatureAlgorithm = createTestAlgorithm()
        const largeSignature = new Uint8Array(256).fill(0xab) // 256 bytes of 0xAB
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm,
            signature: largeSignature,
        })

        const asn1 = ocspSignature.toAsn1()
        const parsed = OCSPSignature.fromAsn1(asn1)

        expect(parsed.signature).toEqual(largeSignature)
    })

    it('should preserve signature algorithm parameters', () => {
        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
            parameters: null,
        }) // With NULL parameters
        const signature = createTestSignature()
        const ocspSignature = new OCSPSignature({
            signatureAlgorithm,
            signature,
        })

        const asn1 = ocspSignature.toAsn1()
        const parsed = OCSPSignature.fromAsn1(asn1)

        expect(parsed.signatureAlgorithm.algorithm).toEqual(
            signatureAlgorithm.algorithm,
        )
        expect(parsed.signatureAlgorithm.parameters).toEqual({
            derBytes: new Uint8Array([5, 0]),
        }) // ASN.1 NULL
    })
})
