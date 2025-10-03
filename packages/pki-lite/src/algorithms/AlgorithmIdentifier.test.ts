import { assert, describe, expect, test } from 'vitest'
import { AlgorithmIdentifier } from './AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { RSAESOAEPParams } from './RSAESOAEPParams.js'
import { Any } from '../asn1/Any.js'

describe('AlgorithmIdentifier', () => {
    test('can be created', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256 with RSA
        expect(algId).toBeInstanceOf(AlgorithmIdentifier)
        expect(algId.algorithm.toString()).toEqual('1.2.840.113549.1.1.11')
        expect(algId.parameters).toBeUndefined()
    })

    test('can be created with parameters', () => {
        const params = null
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
            parameters: params,
        })

        expect(algId).toBeInstanceOf(AlgorithmIdentifier)
        expect(algId.algorithm.toString()).toEqual('1.2.840.113549.1.1.11')
        expect(algId.parameters).toEqual({
            derBytes: null,
        })
    })

    test('can be converted into ASN.1 without parameters', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        const asn1 = algId.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(1)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.ObjectIdentifier)

        assert(asn1.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)
        // The toString() method includes "OBJECT IDENTIFIER : " prefix
        expect(asn1.valueBlock.value[0].toString()).toEqual(
            'OBJECT IDENTIFIER : 1.2.840.113549.1.1.11',
        )
    })

    test('can be converted into ASN.1 with parameters', () => {
        // Use a simple parameter that can be converted
        const params = new Any({ derBytes: new Uint8Array([1, 2, 3, 4]) })
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
            parameters: params,
        })
        const asn1 = algId.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.ObjectIdentifier)
        assert(asn1.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)
        // The toString() method includes "OBJECT IDENTIFIER : " prefix
        expect(asn1.valueBlock.value[0].toString()).toEqual(
            'OBJECT IDENTIFIER : 1.2.840.113549.1.1.11',
        )
        // Check that the second value exists but don't check its exact type
        expect(asn1.valueBlock.value[1]).toBeDefined()
    })

    test('can be parsed from ASN.1', () => {
        // Create ASN.1 sequence with algorithm OID
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.1.11' }),
            ],
        })

        const algId = AlgorithmIdentifier.fromAsn1(asn1)
        expect(algId).toBeInstanceOf(AlgorithmIdentifier)
        expect(algId.algorithm.toString()).toEqual('1.2.840.113549.1.1.11')
        expect(algId.parameters).toBeUndefined()
    })

    test('can be parsed from ASN.1 with parameters', () => {
        // Create ASN.1 sequence with algorithm OID and parameters
        const paramBytes = new Uint8Array([1, 2, 3, 4])
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.1.11' }),
                new asn1js.OctetString({ valueHex: paramBytes }),
            ],
        })

        const algId = AlgorithmIdentifier.fromAsn1(asn1)
        expect(algId).toBeInstanceOf(AlgorithmIdentifier)
        expect(algId.algorithm.toString()).toEqual('1.2.840.113549.1.1.11')
        expect(algId.parameters).toBeDefined()
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a sequence
        const asn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => AlgorithmIdentifier.fromAsn1(asn1)).toThrow(
            'Expected Sequence',
        )
    })

    test('throws an error when algorithm is not an ObjectIdentifier', () => {
        // Create an ASN.1 sequence with an invalid algorithm field
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })

        expect(() => AlgorithmIdentifier.fromAsn1(asn1)).toThrow(
            'Expected ObjectIdentifier for algorithm',
        )
    })

    test('common algorithm names for RSA and signatures', () => {
        const testCases = [
            { oid: '1.2.840.113549.1.1.1', expected: 'RSA' },
            { oid: '1.2.840.113549.1.1.5', expected: 'SHA1withRSA' },
            { oid: '1.2.840.113549.1.1.11', expected: 'SHA256withRSA' },
            { oid: '1.2.840.113549.1.1.12', expected: 'SHA384withRSA' },
            { oid: '1.2.840.113549.1.1.13', expected: 'SHA512withRSA' },
            { oid: '1.2.840.10040.4.1', expected: 'DSA' },
            { oid: '1.2.840.10045.2.1', expected: 'ECDSA' },
            { oid: '1.2.840.10045.4.3.2', expected: 'SHA256withECDSA' },
        ]

        for (const { oid, expected } of testCases) {
            const algId = new AlgorithmIdentifier({ algorithm: oid })
            expect(algId.friendlyName).toEqual(expected)
        }
    })

    test('common algorithm names for hash functions', () => {
        const testCases = [
            { oid: '1.3.14.3.2.26', expected: 'SHA1' },
            { oid: '2.16.840.1.101.3.4.2.1', expected: 'SHA256' },
            { oid: '2.16.840.1.101.3.4.2.2', expected: 'SHA384' },
            { oid: '2.16.840.1.101.3.4.2.3', expected: 'SHA512' },
            { oid: '1.2.840.113549.2.5', expected: 'MD5' },
        ]

        for (const { oid, expected } of testCases) {
            const algId = new AlgorithmIdentifier({ algorithm: oid })
            expect(algId.friendlyName).toEqual(expected)
        }
    })

    test('common algorithm names for encryption algorithms', () => {
        const testCases = [
            { oid: '2.16.840.1.101.3.4.1.2', expected: 'AES-128-CBC' },
            { oid: '2.16.840.1.101.3.4.1.42', expected: 'AES-256-CBC' },
            { oid: '2.16.840.1.101.3.4.1.6', expected: 'AES-128-GCM' },
            { oid: '2.16.840.1.101.3.4.1.46', expected: 'AES-256-GCM' },
        ]

        for (const { oid, expected } of testCases) {
            const algId = new AlgorithmIdentifier({ algorithm: oid })
            expect(algId.friendlyName).toEqual(expected)
        }
    })

    test('common algorithm names for X.509 extensions', () => {
        const testCases = [
            { oid: '2.5.29.14', expected: 'Subject Key Identifier' },
            { oid: '2.5.29.15', expected: 'Key Usage' },
            { oid: '2.5.29.17', expected: 'Subject Alternative Name' },
            { oid: '2.5.29.19', expected: 'Basic Constraints' },
            { oid: '2.5.29.35', expected: 'Authority Key Identifier' },
        ]

        for (const { oid, expected } of testCases) {
            const algId = new AlgorithmIdentifier({ algorithm: oid })
            expect(algId.friendlyName).toEqual(expected)
        }
    })

    test('common algorithm names for extended key usage', () => {
        const testCases = [
            {
                oid: '1.3.6.1.5.5.7.3.1',
                expected: 'TLS Web Server Authentication',
            },
            {
                oid: '1.3.6.1.5.5.7.3.2',
                expected: 'TLS Web Client Authentication',
            },
            { oid: '1.3.6.1.5.5.7.3.3', expected: 'Code Signing' },
            { oid: '1.3.6.1.5.5.7.3.4', expected: 'Email Protection' },
            { oid: '1.3.6.1.5.5.7.3.8', expected: 'Time Stamping' },
        ]

        for (const { oid, expected } of testCases) {
            const algId = new AlgorithmIdentifier({ algorithm: oid })
            expect(algId.friendlyName).toEqual(expected)
        }
    })

    test('unknown OIDs return the OID itself', () => {
        const unknownOid = '1.2.3.4.5.6.7.8.9'
        const algId = new AlgorithmIdentifier({ algorithm: unknownOid })
        expect(algId.friendlyName).toEqual(unknownOid)
    })

    test('toString snapshot', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        }) // SHA256withRSA
        expect(algId.toString()).toMatchInlineSnapshot(`
          "[AlgorithmIdentifier] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.1.11"
        `)
    })

    test('toString snapshot with parameters', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
            parameters: null,
        })
        expect(algId.toString()).toMatchInlineSnapshot(`
          "[AlgorithmIdentifier] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
            NULL"
        `)
    })

    test('toPem snapshot', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
        })
        expect(algId.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ALGORITHMIDENTIFIER-----
          MAsGCSqGSIb3DQEBCw==
          -----END ALGORITHMIDENTIFIER-----"
        `)
    })

    test('toPem snapshot with parameters', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
            parameters: null,
        })
        expect(algId.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ALGORITHMIDENTIFIER-----
          MA0GCSqGSIb3DQEBCwUA
          -----END ALGORITHMIDENTIFIER-----"
        `)
    })

    test('parseParameters', () => {
        const algId = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.11',
            parameters: new RSAESOAEPParams(),
        })
        const asn1 = algId.toAsn1()
        const parsed = AlgorithmIdentifier.fromAsn1(asn1)
        const parameters = parsed.parameters?.parseAs(RSAESOAEPParams)
        expect(parameters).toBeInstanceOf(RSAESOAEPParams)
    })
})
