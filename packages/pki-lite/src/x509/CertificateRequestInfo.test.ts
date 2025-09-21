import { assert, describe, expect, test } from 'vitest'
import { CertificateRequestInfo } from './CertificateRequestInfo.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Attribute } from './Attribute.js'
import { asn1js } from '../core/PkiBase.js'
import { RDNSequence } from './RDNSequence.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'

describe('CertificateRequestInfo', () => {
    test('can be created', () => {
        const requestInfo = createSampleRequestInfo()

        expect(requestInfo).toBeInstanceOf(CertificateRequestInfo)
        expect(requestInfo.version).toBe(0)
        expect(requestInfo.publicKey).toBeInstanceOf(SubjectPublicKeyInfo)
        expect(requestInfo.attributes).toBeDefined()
        expect(requestInfo.attributes?.length).toBe(1)
        expect(requestInfo.attributes?.[0]).toBeInstanceOf(Attribute)
    })

    test('can be converted to ASN.1', () => {
        const requestInfo = createSampleRequestInfo()
        const asn1 = requestInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value.length).toBe(4)

        // Check version
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)

        // Check subject
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)

        // Check publicKey
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.Sequence)

        // Check attributes
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value[3]).toBeInstanceOf(asn1js.Constructed)
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value[3].idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value[3].idBlock.tagNumber).toBe(0) // [0]
    })

    test('without attributes', () => {
        const name = createSampleName()
        const publicKey = createSamplePublicKey()

        const requestInfo = new CertificateRequestInfo({
            version: 0,
            subject: name,
            publicKey,
        })

        expect(requestInfo.attributes).toBeUndefined()

        const asn1 = requestInfo.toAsn1()
        // @ts-ignore - valueBlock.value exists at runtime but not in typings
        expect(asn1.valueBlock.value.length).toBe(3) // No attributes
    })

    test('can be parsed from ASN.1 without attributes', () => {
        // Create the ASN.1 structure
        const version = 0
        const subject = createSampleName()
        const publicKey = createSamplePublicKey()

        // Mock the required fromAsn1 methods
        const originalRDNSequenceFromAsn1 = RDNSequence.fromAsn1
        const originalSubjectPublicKeyInfoFromAsn1 =
            SubjectPublicKeyInfo.fromAsn1

        RDNSequence.fromAsn1 = function () {
            return subject
        } as any

        SubjectPublicKeyInfo.fromAsn1 = function () {
            return publicKey
        } as any

        try {
            const asn1 = new asn1js.Sequence({
                value: [
                    new asn1js.Integer({ value: version }),
                    new asn1js.Sequence({}), // Subject
                    new asn1js.Sequence({}), // PublicKey
                ],
            })

            const requestInfo = CertificateRequestInfo.fromAsn1(asn1)
            expect(requestInfo).toBeInstanceOf(CertificateRequestInfo)
            expect(requestInfo.version).toBe(version)
            expect(requestInfo.subject).toBe(subject)
            expect(requestInfo.publicKey).toBe(publicKey)
            expect(requestInfo.attributes).toBeUndefined()
        } finally {
            // Restore original methods
            RDNSequence.fromAsn1 = originalRDNSequenceFromAsn1
            SubjectPublicKeyInfo.fromAsn1 = originalSubjectPublicKeyInfoFromAsn1
        }
    })

    test('can be parsed from ASN.1 with attributes', () => {
        // Create the ASN.1 structure
        const version = 0
        const subject = createSampleName()
        const publicKey = createSamplePublicKey()
        const attributes = [
            new Attribute({
                type: '1.2.840.113549.1.9.14',
                // extensionRequest
                values: [new Uint8Array([1, 2, 3])],
            }),
        ]

        // Mock the required fromAsn1 methods
        const originalRDNSequenceFromAsn1 = RDNSequence.fromAsn1
        const originalSubjectPublicKeyInfoFromAsn1 =
            SubjectPublicKeyInfo.fromAsn1
        const originalAttributeFromAsn1 = Attribute.fromAsn1

        RDNSequence.fromAsn1 = function () {
            return subject
        } as any

        SubjectPublicKeyInfo.fromAsn1 = function () {
            return publicKey
        } as any

        Attribute.fromAsn1 = function () {
            return attributes[0]
        } as any

        try {
            const asn1 = new asn1js.Sequence({
                value: [
                    new asn1js.Integer({ value: version }),
                    new asn1js.Sequence({}), // Subject
                    new asn1js.Sequence({}), // PublicKey
                    new asn1js.Constructed({
                        idBlock: {
                            tagClass: 3, // CONTEXT_SPECIFIC
                            tagNumber: 0, // [0]
                        },
                        value: [
                            new asn1js.Set({
                                value: [
                                    new asn1js.Sequence({}), // Attribute
                                ],
                            }),
                        ],
                    }),
                ],
            })

            const requestInfo = CertificateRequestInfo.fromAsn1(asn1)
            expect(requestInfo).toBeInstanceOf(CertificateRequestInfo)
            expect(requestInfo.version).toBe(version)
            expect(requestInfo.subject).toBe(subject)
            expect(requestInfo.publicKey).toBe(publicKey)
            expect(requestInfo.attributes).toBeDefined()
            expect(requestInfo.attributes?.length).toBe(1)
            expect(requestInfo.attributes?.[0]).toBe(attributes[0])
        } finally {
            // Restore original methods
            RDNSequence.fromAsn1 = originalRDNSequenceFromAsn1
            SubjectPublicKeyInfo.fromAsn1 = originalSubjectPublicKeyInfoFromAsn1
            Attribute.fromAsn1 = originalAttributeFromAsn1
        }
    })

    test('fromAsn1 throws error for non-sequence', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Sequence({}),
                // Missing publicKey
            ],
        })
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 3 or 4 elements',
        )
    })

    test('fromAsn1 throws error for invalid version', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.BitString({}), // Not an Integer
                new asn1js.Sequence({}),
                new asn1js.Sequence({}),
            ],
        })
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: version must be an INTEGER',
        )
    })

    test('fromAsn1 throws error for invalid subject', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Integer({ value: 1 }), // Not a Sequence
                new asn1js.Sequence({}),
            ],
        })
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: subject must be a SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid publicKey', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Sequence({}),
                new asn1js.Integer({ value: 1 }), // Not a Sequence
            ],
        })
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: publicKey must be a SEQUENCE',
        )
    })

    test('CertificateRequestInfo toString snapshot', () => {
        const obj = createSampleRequestInfo()
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[CertificateRequestInfo] SEQUENCE :
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
                    BOOLEAN: FALSE"
        `)
    })

    test('CertificateRequestInfo toString snapshot without attributes', () => {
        const name = createSampleName()
        const publicKey = createSamplePublicKey()
        const obj = new CertificateRequestInfo({
            version: 0,
            subject: name,
            publicKey,
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[CertificateRequestInfo] SEQUENCE :
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
              BIT STRING : 0000000100000010000000110000010000000101"
        `)
    })

    test('CertificateRequestInfo toPem snapshot', () => {
        const obj = createSampleRequestInfo()
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN CERTIFICATEREQUESTINFO-----
          MHICAQAwQDEVMBMGA1UEAxMMVGVzdCBSZXF1ZXN0MRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCVVMwFTALBgkqhkiG9w0BAQEDBgABAgMEBaAUMRIwEAYJKoZIhvcNAQkOMQMBAQA=
          -----END CERTIFICATEREQUESTINFO-----"
        `)
    })

    test('CertificateRequestInfo toPem snapshot without attributes', () => {
        const name = createSampleName()
        const publicKey = createSamplePublicKey()
        const obj = new CertificateRequestInfo({
            version: 0,
            subject: name,
            publicKey,
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN CERTIFICATEREQUESTINFO-----
          MFwCAQAwQDEVMBMGA1UEAxMMVGVzdCBSZXF1ZXN0MRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCVVMwFTALBgkqhkiG9w0BAQEDBgABAgMEBQ==
          -----END CERTIFICATEREQUESTINFO-----"
        `)
    })
})

/**
 * Creates a sample name for testing.
 */
function createSampleName(): RDNSequence {
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

/**
 * Creates a sample key for testing.
 */
function createSamplePublicKey(): SubjectPublicKeyInfo {
    const publicKeyData = new Uint8Array([1, 2, 3, 4, 5])
    const algorithm = new AlgorithmIdentifier({
        algorithm: '1.2.840.113549.1.1.1',
    }) // RSA
    return new SubjectPublicKeyInfo({
        algorithm,
        subjectPublicKey: publicKeyData,
    })
}

/**
 * Creates a sample certificate request info for testing.
 */
function createSampleRequestInfo(): CertificateRequestInfo {
    const name = createSampleName()
    const publicKey = createSamplePublicKey()

    const attributes = [
        new Attribute({
            type: '1.2.840.113549.1.9.14',
            // extensionRequest
            values: [new Uint8Array([1, 2, 3])],
        }),
    ]

    return new CertificateRequestInfo({
        version: 0,
        subject: name,
        publicKey,
        attributes,
    })
}
