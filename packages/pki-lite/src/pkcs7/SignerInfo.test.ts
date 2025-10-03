import { describe, test, expect, beforeEach } from 'vitest'
import { SignerInfo } from './SignerInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'
import { Name } from '../x509/Name.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { Attribute } from '../x509/Attribute.js'
import { asn1js } from '../core/PkiBase.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'

describe('SignerInfo', () => {
    let issuerAndSerialNumber: IssuerAndSerialNumber
    let digestAlgorithm: AlgorithmIdentifier
    let signatureAlgorithm: AlgorithmIdentifier
    let signature: Uint8Array<ArrayBuffer>

    beforeEach(() => {
        // Create test issuer
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test Signer',
                }),
                new AttributeTypeAndValue({
                    type: '2.5.4.6',
                    value: 'US',
                }),
            ),
        )

        issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer,
            serialNumber: 12345,
        })

        digestAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1', // SHA-256
        })

        signatureAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1', // RSA
        })

        // Mock signature bytes
        signature = new Uint8Array(256)
        for (let i = 0; i < signature.length; i++) {
            signature[i] = i % 256
        }
    })

    test('can be created with minimal parameters', () => {
        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
        })

        expect(signerInfo.version).toEqual(1)
        expect(signerInfo.sid).toEqual(issuerAndSerialNumber)
        expect(signerInfo.digestAlgorithm).toEqual(digestAlgorithm)
        expect(signerInfo.signatureAlgorithm).toEqual(signatureAlgorithm)
        expect(signerInfo.signature).toEqual(signature)
        expect(signerInfo.signedAttrs).toBeUndefined()
        expect(signerInfo.unsignedAttrs).toBeUndefined()
    })

    test('can be created with signed attributes', () => {
        const signedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.3', // contentType
                values: [
                    new ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
                ],
            }),
            new Attribute({
                type: '1.2.840.113549.1.9.4', // messageDigest
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(32) }),
                ],
            }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
        })

        expect(signerInfo.signedAttrs).toBeDefined()
        expect(signerInfo.signedAttrs!.length).toEqual(2)
        expect(signerInfo.unsignedAttrs).toBeUndefined()
    })

    test('can be created with unsigned attributes', () => {
        const unsignedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.6', // counterSignature
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(128) }),
                ],
            }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            unsignedAttrs,
        })

        expect(signerInfo.signedAttrs).toBeUndefined()
        expect(signerInfo.unsignedAttrs).toBeDefined()
        expect(signerInfo.unsignedAttrs!.length).toEqual(1)
    })

    test('can be created with both signed and unsigned attributes', () => {
        const signedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.3',
                values: [
                    new ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
                ],
            }),
        ]

        const unsignedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.6',
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(128) }),
                ],
            }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
            unsignedAttrs,
        })

        expect(signerInfo.signedAttrs).toBeDefined()
        expect(signerInfo.signedAttrs!.length).toEqual(1)
        expect(signerInfo.unsignedAttrs).toBeDefined()
        expect(signerInfo.unsignedAttrs!.length).toEqual(1)
    })

    test('can be converted to ASN.1 with minimal parameters', () => {
        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
        })

        const asn1 = signerInfo.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const sequence = asn1 as asn1js.Sequence
        // Should have: version, sid, digestAlgorithm, signatureAlgorithm, signature (5 elements)
        expect(sequence.valueBlock.value.length).toEqual(5)

        // Check version
        expect(sequence.valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)
        const version = sequence.valueBlock.value[0] as asn1js.Integer
        expect(version.valueBlock.valueDec).toEqual(1)
    })

    test('can be converted to ASN.1 with signed attributes', () => {
        const signedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.3',
                values: [
                    new ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
                ],
            }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
        })

        const asn1 = signerInfo.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const sequence = asn1 as asn1js.Sequence
        // Should have: version, sid, digestAlgorithm, signedAttrs[0], signatureAlgorithm, signature (6 elements)
        expect(sequence.valueBlock.value.length).toEqual(6)
    })

    test('can be converted to ASN.1 with unsigned attributes', () => {
        const unsignedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.6',
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(128) }),
                ],
            }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            unsignedAttrs,
        })

        const asn1 = signerInfo.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const sequence = asn1 as asn1js.Sequence
        // Should have: version, sid, digestAlgorithm, signatureAlgorithm, signature, unsignedAttrs[1] (6 elements)
        expect(sequence.valueBlock.value.length).toEqual(6)
    })

    test('can be converted to ASN.1 with both signed and unsigned attributes', () => {
        const signedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.3',
                values: [
                    new ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
                ],
            }),
        ]

        const unsignedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.6',
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(128) }),
                ],
            }),
        ]

        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
            unsignedAttrs,
        })

        const asn1 = signerInfo.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const sequence = asn1 as asn1js.Sequence
        // Should have: version, sid, digestAlgorithm, signedAttrs[0], signatureAlgorithm, signature, unsignedAttrs[1] (7 elements)
        expect(sequence.valueBlock.value.length).toEqual(7)
    })

    test('can be created from ASN.1', () => {
        const originalSignerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
        })

        const asn1 = originalSignerInfo.toAsn1()
        const reconstructedSignerInfo = SignerInfo.fromAsn1(asn1)

        expect(reconstructedSignerInfo.version).toEqual(1)
        expect(
            reconstructedSignerInfo.digestAlgorithm.algorithm.toString(),
        ).toEqual(digestAlgorithm.algorithm.toString())
        expect(
            reconstructedSignerInfo.signatureAlgorithm.algorithm.toString(),
        ).toEqual(signatureAlgorithm.algorithm.toString())
        expect(reconstructedSignerInfo.signature).toEqual(signature)
    })

    test('roundtrip conversion preserves data', () => {
        const signedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.3',
                values: [
                    new ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }),
                ],
            }),
            new Attribute({
                type: '1.2.840.113549.1.9.4',
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(32) }),
                ],
            }),
        ]

        const unsignedAttrs = [
            new Attribute({
                type: '1.2.840.113549.1.9.6',
                values: [
                    new asn1js.OctetString({ valueHex: new Uint8Array(128) }),
                ],
            }),
        ]

        const originalSignerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs,
            unsignedAttrs,
        })

        const asn1 = originalSignerInfo.toAsn1()
        const reconstructedSignerInfo = SignerInfo.fromAsn1(asn1)

        expect(reconstructedSignerInfo.version).toEqual(
            originalSignerInfo.version,
        )
        expect(
            reconstructedSignerInfo.digestAlgorithm.algorithm.toString(),
        ).toEqual(originalSignerInfo.digestAlgorithm.algorithm.toString())
        expect(
            reconstructedSignerInfo.signatureAlgorithm.algorithm.toString(),
        ).toEqual(originalSignerInfo.signatureAlgorithm.algorithm.toString())
        expect(reconstructedSignerInfo.signature).toEqual(
            originalSignerInfo.signature,
        )
        expect(reconstructedSignerInfo.signedAttrs?.length).toEqual(
            originalSignerInfo.signedAttrs?.length,
        )
        expect(reconstructedSignerInfo.unsignedAttrs?.length).toEqual(
            originalSignerInfo.unsignedAttrs?.length,
        )
    })

    test('fromAsn1 throws error for invalid structure', () => {
        const invalidAsn1 = new asn1js.OctetString({
            valueHex: new Uint8Array(10),
        })
        expect(() => SignerInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence',
        )
    })

    test('fromAsn1 throws error for insufficient elements', () => {
        const incompleteSequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                // Missing required elements
            ],
        })
        expect(() => SignerInfo.fromAsn1(incompleteSequence)).toThrow(
            'Invalid ASN.1 structure: expected at least 5 elements',
        )
    })

    test('toDer produces valid DER encoding', () => {
        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
        })

        const derBytes = signerInfo.toDer()
        expect(derBytes).toBeInstanceOf(Uint8Array<ArrayBuffer>)
        expect(derBytes.length).toBeGreaterThan(0)

        // Verify it can be parsed back by converting to ASN.1 first
        const reconstructed = SignerInfo.fromDer(derBytes)
        expect(reconstructed.version).toEqual(signerInfo.version)
    })

    test('handles empty signed attributes array', () => {
        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            signedAttrs: [], // Empty array
        })

        expect(signerInfo.signedAttrs).toBeUndefined()
    })

    test('handles empty unsigned attributes array', () => {
        const signerInfo = new SignerInfo({
            version: 1,
            sid: issuerAndSerialNumber,
            digestAlgorithm,
            signatureAlgorithm,
            signature,
            unsignedAttrs: [], // Empty array
        })

        expect(signerInfo.unsignedAttrs).toBeUndefined()
    })
})
