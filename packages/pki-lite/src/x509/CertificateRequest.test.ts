import { assert, describe, expect, test } from 'vitest'
import { CertificateRequest } from './CertificateRequest.js'
import { CertificateRequestInfo } from './CertificateRequestInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'
import { Attribute } from './Attribute.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'
import { RDNSequence } from './RDNSequence.js'
import { BitString } from '../asn1/BitString.js'

describe('CertificateRequest', () => {
    test('can be created', () => {
        const request = createSampleRequest()

        expect(request).toBeInstanceOf(CertificateRequest)
        expect(request.requestInfo).toBeDefined()
        expect(request.signatureAlgorithm).toBeInstanceOf(AlgorithmIdentifier)
        expect(request.signature).toBeInstanceOf(BitString)
    })

    test('can be converted into ASN.1', () => {
        const request = createSampleRequest()
        const asn1 = request.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3)

        // First element should be the requestInfo (a Sequence)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)

        // Second element should be the signatureAlgorithm (a Sequence)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)

        // Third element should be the signature (a BitString)
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.BitString)
    })

    test('can be parsed from ASN.1', () => {
        const request = createSampleRequest()
        const asn1 = request.toAsn1()

        // Mock the CertificateRequestInfo.fromAsn1 method since it's not implemented yet
        const originalFromAsn1 = CertificateRequestInfo.fromAsn1
        CertificateRequestInfo.fromAsn1 = function (asn1: any) {
            return request.requestInfo
        } as any

        try {
            const parsedRequest = CertificateRequest.fromAsn1(asn1)

            expect(parsedRequest).toBeInstanceOf(CertificateRequest)
            expect(parsedRequest.requestInfo).toEqual(request.requestInfo)
            expect(parsedRequest.signatureAlgorithm.algorithm).toEqual(
                request.signatureAlgorithm.algorithm,
            )
            expect(parsedRequest.signature).toEqual(request.signature)
        } finally {
            // Restore the original method
            CertificateRequestInfo.fromAsn1 = originalFromAsn1
        }
    })

    test('fromAsn1 throws error for non-sequence', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => CertificateRequest.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({}),
                new asn1js.Sequence({}),
                // Missing signature
            ],
        })
        expect(() => CertificateRequest.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 3 elements',
        )
    })

    test('fromAsn1 throws error for invalid requestInfo', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // Not a sequence
                new asn1js.Sequence({}),
                new asn1js.BitString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })
        expect(() => CertificateRequest.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: requestInfo must be a SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid signatureAlgorithm', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({}),
                new asn1js.Integer({ value: 1 }), // Not a sequence
                new asn1js.BitString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })
        expect(() => CertificateRequest.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: signatureAlgorithm must be a SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid signature', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({}),
                new asn1js.Sequence({}),
                new asn1js.Integer({ value: 1 }), // Not a BitString
            ],
        })
        expect(() => CertificateRequest.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: signature must be a BIT STRING',
        )
    })

    test('CertificateRequest toString snapshot', () => {
        const request = createSampleRequest()
        expect(request.toString()).toMatchInlineSnapshot(`
          "[CertificateRequest] SEQUENCE :
            SEQUENCE :
              INTEGER : 0
              SEQUENCE :
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.3
                    PrintableString : 'Test Request'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.10
                    PrintableString : 'Test Organization'
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 2.5.4.6
                    PrintableString : 'US'
              SEQUENCE :
                SEQUENCE :
                  OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
                BIT STRING : 0000000100000010000000110000010000000101
              [0] :
                SET :
                  SEQUENCE :
                    OBJECT IDENTIFIER : 1.2.840.113549.1.9.14
                    SET :
                      BOOLEAN: FALSE
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
            BIT STRING : 0000101000010100000111100010100000110010"
        `)
    })

    test('CertificateRequest toPem snapshot', () => {
        const request = createSampleRequest()
        expect(request.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN CERTIFICATEREQUEST-----
          MIGJMHICAQAwQDEVMBMGA1UEAxMMVGVzdCBSZXF1ZXN0MRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCVVMwFTALBgkqhkiG9w0BAQEDBgABAgMEBaAUMRIwEAYJKoZIhvcNAQkOMQMBAQAwCwYJKoZIhvcNAQELAwYAChQeKDI=
          -----END CERTIFICATEREQUEST-----"
        `)
    })
})

/**
 * Creates a sample certificate request for testing.
 */
function createSampleRequest(): CertificateRequest {
    // Create subject name
    const createName = (): RDNSequence => {
        const cn = new AttributeTypeAndValue({
            type: '2.5.4.3',
            value: 'Test Request',
        })
        const cnRdn = new RelativeDistinguishedName()
        cnRdn.push(cn)

        const o = new AttributeTypeAndValue({
            type: '2.5.4.10',
            value: 'Test Organization',
        })
        const oRdn = new RelativeDistinguishedName()
        oRdn.push(o)

        const c = new AttributeTypeAndValue({ type: '2.5.4.6', value: 'US' })
        const cRdn = new RelativeDistinguishedName()
        cRdn.push(c)

        const name = new RDNSequence()
        name.push(cnRdn, oRdn, cRdn)

        return name
    }

    // Create a sample key info
    const publicKeyData = new Uint8Array([1, 2, 3, 4, 5])
    const algorithm = new AlgorithmIdentifier({
        algorithm: '1.2.840.113549.1.1.1',
    }) // RSA
    const publicKey = new SubjectPublicKeyInfo({
        algorithm,
        subjectPublicKey: publicKeyData,
    })

    // Create request information
    const attributes = [
        new Attribute({
            type: '1.2.840.113549.1.9.14',
            // extensionRequest
            values: [new Uint8Array([1, 2, 3])],
        }),
    ]

    const requestInfo = new CertificateRequestInfo({
        version: 0,
        subject: createName(),
        publicKey,
        attributes,
    })

    // Create signature (just a placeholder for testing)
    const signatureValue = new Uint8Array([10, 20, 30, 40, 50])

    // Create the certificate request
    return new CertificateRequest({
        requestInfo,
        signatureAlgorithm: new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }), // SHA256 with RSA
        signature: signatureValue,
    })
}
