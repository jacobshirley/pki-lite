import { assert, describe, expect, test } from 'vitest'
import { CertificateRequestInfo } from './CertificateRequestInfo.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Attribute } from './Attribute.js'
import { der, TagClass, UniversalTag } from '../core/PkiBase.js'
import { RDNSequence } from './RDNSequence.js'
import { SubjectPublicKeyInfo } from '../keys/SubjectPublicKeyInfo.js'

describe('CertificateRequestInfo', () => {
    test('can be created', () => {
        const requestInfo = createSampleRequestInfo()

        expect(requestInfo).toBeInstanceOf(CertificateRequestInfo)
        expect(requestInfo.version).toEqual(0)
        expect(requestInfo.publicKey).toBeInstanceOf(SubjectPublicKeyInfo)
        expect(requestInfo.attributes).toBeDefined()
        expect(requestInfo.attributes?.length).toEqual(1)
        expect(requestInfo.attributes?.[0]).toBeInstanceOf(Attribute)
    })

    test('can be converted to ASN.1', () => {
        const requestInfo = createSampleRequestInfo()
        const asn1 = requestInfo.toAsn1()

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(4)

        // Check version
        expect(asn1.children[0].is(UniversalTag.Integer)).toBe(true)

        // Check subject
        expect(asn1.children[1].is(UniversalTag.Sequence)).toBe(true)

        // Check publicKey
        expect(asn1.children[2].is(UniversalTag.Sequence)).toBe(true)

        // Check attributes
        expect(asn1.children[3].constructed).toBe(true)
        expect(asn1.children[3].tagClass).toEqual(TagClass.Context) // CONTEXT-SPECIFIC
        expect(asn1.children[3].tag).toEqual(0) // [0]
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
        // PKCS#10 makes `attributes [0]` mandatory: without attributes it is written
        // as an empty [0] (A0 00), which is what OpenSSL does too.
        const children = asn1.children
        expect(children.length).toEqual(4)
        expect(children[3].tagClass).toEqual(TagClass.Context)
        expect(children[3].tag).toEqual(0)
        expect(children[3].children.length).toEqual(0)
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
            const asn1 = der.sequence([
                der.integer(version),
                der.sequence([]), // Subject
                der.sequence([]), // PublicKey
            ])

            const requestInfo = CertificateRequestInfo.fromAsn1(asn1)
            expect(requestInfo).toBeInstanceOf(CertificateRequestInfo)
            expect(requestInfo.version).toEqual(version)
            expect(requestInfo.subject).toEqual(subject)
            expect(requestInfo.publicKey).toEqual(publicKey)
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
                values: [new Uint8Array([0x30, 0x00])], // empty Extensions
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
            const asn1 = der.sequence([
                der.integer(version),
                der.sequence([]), // Subject
                der.sequence([]), // PublicKey
                der.constructed(0, [
                    der.set([
                        der.sequence([]), // Attribute
                    ]),
                ]),
            ])

            const requestInfo = CertificateRequestInfo.fromAsn1(asn1)
            expect(requestInfo).toBeInstanceOf(CertificateRequestInfo)
            expect(requestInfo.version).toEqual(version)
            expect(requestInfo.subject).toEqual(subject)
            expect(requestInfo.publicKey).toEqual(publicKey)
            expect(requestInfo.attributes).toBeDefined()
            expect(requestInfo.attributes?.length).toEqual(1)
            expect(requestInfo.attributes?.[0]).toEqual(attributes[0])
        } finally {
            // Restore original methods
            RDNSequence.fromAsn1 = originalRDNSequenceFromAsn1
            SubjectPublicKeyInfo.fromAsn1 = originalSubjectPublicKeyInfoFromAsn1
            Attribute.fromAsn1 = originalAttributeFromAsn1
        }
    })

    test('fromAsn1 throws error for non-sequence', () => {
        const asn1 = der.integer(1)
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = der.sequence([
            der.integer(0),
            der.sequence([]),
            // Missing publicKey
        ])
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 3 or 4 elements',
        )
    })

    test('fromAsn1 throws error for invalid version', () => {
        const asn1 = der.sequence([
            der.bitString(new Uint8Array(0)), // Not an Integer
            der.sequence([]),
            der.sequence([]),
        ])
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: version must be an INTEGER',
        )
    })

    test('fromAsn1 throws error for invalid subject', () => {
        const asn1 = der.sequence([
            der.integer(0),
            der.integer(1), // Not a Sequence
            der.sequence([]),
        ])
        expect(() => CertificateRequestInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: subject must be a SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid publicKey', () => {
        const asn1 = der.sequence([
            der.integer(0),
            der.sequence([]),
            der.integer(1), // Not a Sequence
        ])
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
              SEQUENCE :
                OBJECT IDENTIFIER : 1.2.840.113549.1.9.14
                SET :
                  SEQUENCE :"
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
              BIT STRING : 0000000100000010000000110000010000000101
            [0] :"
        `)
    })

    test('CertificateRequestInfo toPem snapshot', () => {
        const obj = createSampleRequestInfo()
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN CERTIFICATEREQUESTINFO-----
          MG8CAQAwQDEVMBMGA1UEAxMMVGVzdCBSZXF1ZXN0MRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCVVMwFTALBgkqhkiG9w0BAQEDBgABAgMEBaARMA8GCSqGSIb3DQEJDjECMAA=
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
          MF4CAQAwQDEVMBMGA1UEAxMMVGVzdCBSZXF1ZXN0MRowGAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCVVMwFTALBgkqhkiG9w0BAQEDBgABAgMEBaAA
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
            values: [new Uint8Array([0x30, 0x00])], // empty Extensions
        }),
    ]

    return new CertificateRequestInfo({
        version: 0,
        subject: name,
        publicKey,
        attributes,
    })
}
