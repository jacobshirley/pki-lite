import { describe, expect, test } from 'vitest'
import { Asn1Node, der, UniversalTag } from '../core/PkiBase.js'
import { ECPrivateKey } from './ECPrivateKey.js'
import { OIDs } from '../core/OIDs.js'

describe('ECPrivateKey', () => {
    // Sample private key data for testing
    const privateKeyBytes = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ])

    const publicKeyBytes = new Uint8Array([
        0x04, // Uncompressed point format
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
        0x00,
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0xfe,
        0xdc,
        0xba,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
        0x00,
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef,
        0xfe,
        0xdc,
        0xba,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    ])

    test('constructor creates ECPrivateKey with correct properties', () => {
        const ecPrivKey = new ECPrivateKey({
            privateKey: privateKeyBytes,
            namedCurve: OIDs.CURVES.SECP256R1,
            publicKey: publicKeyBytes,
        })

        expect(ecPrivKey.version).toEqual(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toEqual(OIDs.CURVES.SECP256R1)
        expect(ecPrivKey.publicKey).toEqual(publicKeyBytes)
    })

    test('toAsn1 correctly encodes ECPrivateKey with all fields', () => {
        const ecPrivKey = new ECPrivateKey({
            privateKey: privateKeyBytes,
            namedCurve: OIDs.CURVES.SECP256R1,
            publicKey: publicKeyBytes,
        })

        const asn1 = ecPrivKey.toAsn1()

        // Should be a SEQUENCE
        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        const values = asn1.children

        // Should have 4 elements: version, privateKey, [0] parameters, [1] publicKey
        expect(values.length).toEqual(4)

        // Version
        expect(values[0].is(UniversalTag.Integer)).toBe(true)
        expect(der.readNumber(values[0])).toEqual(1)

        // PrivateKey
        expect(values[1].is(UniversalTag.OctetString)).toBe(true)
        expect(new Uint8Array(values[1].bytes())).toEqual(privateKeyBytes)

        // Parameters [0]
        expect(values[2].constructed).toBe(true)
        expect(values[2].tag).toEqual(0)

        const parametersValue = values[2].children
        expect(parametersValue.length).toEqual(1)
        expect(parametersValue[0].is(UniversalTag.ObjectIdentifier)).toBe(true)
        expect(der.readOid(parametersValue[0])).toEqual(OIDs.CURVES.SECP256R1)

        // PublicKey [1]
        expect(values[3].constructed).toBe(true)
        expect(values[3].tag).toEqual(1)

        const publicKeyValue = values[3].children
        expect(publicKeyValue.length).toEqual(1)
        expect(publicKeyValue[0].is(UniversalTag.BitString)).toBe(true)
    })

    test('toAsn1 correctly encodes ECPrivateKey with only required fields', () => {
        const ecPrivKey = new ECPrivateKey({
            privateKey: privateKeyBytes,
        })

        const asn1 = ecPrivKey.toAsn1()

        // Should be a SEQUENCE
        expect(asn1.is(UniversalTag.Sequence)).toBe(true)

        const values = asn1.children

        // Should have only 2 elements: version, privateKey
        expect(values.length).toEqual(2)

        // Version
        expect(values[0].is(UniversalTag.Integer)).toBe(true)
        expect(der.readNumber(values[0])).toEqual(1)

        // PrivateKey
        expect(values[1].is(UniversalTag.OctetString)).toBe(true)
        expect(new Uint8Array(values[1].bytes())).toEqual(privateKeyBytes)
    })

    test('fromAsn1 correctly decodes ECPrivateKey with all fields', () => {
        // Create ASN.1 structure
        const asn1 = der.sequence([
            der.integer(1),
            der.octetString(privateKeyBytes),
            der.constructed(0, [der.oid(OIDs.CURVES.SECP256R1)]),
            der.constructed(1, [der.bitString(publicKeyBytes)]),
        ])

        const ecPrivKey = ECPrivateKey.fromAsn1(asn1)

        expect(ecPrivKey.version).toEqual(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toEqual(OIDs.CURVES.SECP256R1)
        expect(ecPrivKey.publicKey).toEqual(publicKeyBytes)
    })

    test('fromAsn1 correctly decodes ECPrivateKey with only required fields', () => {
        // Create ASN.1 structure
        const asn1 = der.sequence([
            der.integer(1),
            der.octetString(privateKeyBytes),
        ])

        const ecPrivKey = ECPrivateKey.fromAsn1(asn1)

        expect(ecPrivKey.version).toEqual(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toBeUndefined()
        expect(ecPrivKey.publicKey).toBeUndefined()
    })

    test('round-trip encoding and decoding preserves all fields', () => {
        const original = new ECPrivateKey({
            privateKey: privateKeyBytes,
            namedCurve: OIDs.CURVES.SECP256R1,
            publicKey: publicKeyBytes,
        })

        const asn1 = original.toAsn1()
        const decoded = ECPrivateKey.fromAsn1(asn1)

        expect(decoded.version).toEqual(original.version)
        expect(decoded.privateKey).toEqual(original.privateKey)
        expect(decoded.namedCurve).toEqual(original.namedCurve)
        expect(decoded.publicKey).toEqual(original.publicKey)
    })

    test('forCurve static method creates correctly configured ECPrivateKey', () => {
        const ecPrivKey = ECPrivateKey.forCurve(
            OIDs.CURVES.SECP256K1,
            privateKeyBytes,
            publicKeyBytes,
        )

        expect(ecPrivKey.version).toEqual(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toEqual(OIDs.CURVES.SECP256K1)
        expect(ecPrivKey.publicKey).toEqual(publicKeyBytes)
    })

    test('fromAsn1 throws error for invalid ASN.1 structure', () => {
        const invalidAsn1 = der.integer(1)

        expect(() => ECPrivateKey.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid version', () => {
        const asn1 = der.sequence([
            der.integer(2), // Invalid version
            der.octetString(privateKeyBytes),
        ])

        expect(() => ECPrivateKey.fromAsn1(asn1)).toThrow(
            'Invalid EC private key version: expected 1, got 2',
        )
    })

    describe('parameters that are not a named curve', () => {
        const key = (parameters: Asn1Node) =>
            der.sequence([
                der.integer(1),
                der.octetString(new Uint8Array([1, 2, 3])),
                der.constructed(0, [parameters]),
            ])

        test('keeps implicitCurve NULL so the key round-trips', () => {
            const asn1 = key(der.nullValue())
            const parsed = ECPrivateKey.fromAsn1(asn1)
            expect(parsed.namedCurve).toBeUndefined()
            expect(parsed.otherParameters).toBeDefined()
            expect(parsed.toDer()).toEqual(asn1.encode())
        })

        test('rejects parameters of any other type', () => {
            expect(() => ECPrivateKey.fromAsn1(key(der.integer(5)))).toThrow(
                'parameters must be an OBJECT IDENTIFIER',
            )
        })
    })
})
