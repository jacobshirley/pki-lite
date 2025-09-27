import { describe, expect, test } from 'vitest'
import { ECPrivateKey } from './ECPrivateKey.js'
import * as asn1js from 'asn1js'
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

        expect(ecPrivKey.version).toBe(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toBe(OIDs.CURVES.SECP256R1)
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
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const values = (asn1 as asn1js.Sequence).valueBlock.value

        // Should have 4 elements: version, privateKey, [0] parameters, [1] publicKey
        expect(values.length).toBe(4)

        // Version
        expect(values[0]).toBeInstanceOf(asn1js.Integer)
        expect((values[0] as asn1js.Integer).valueBlock.valueDec).toBe(1)

        // PrivateKey
        expect(values[1]).toBeInstanceOf(asn1js.OctetString)
        expect(
            new Uint8Array(
                (values[1] as asn1js.OctetString).valueBlock.valueHexView,
            ),
        ).toEqual(privateKeyBytes)

        // Parameters [0]
        expect(values[2]).toBeInstanceOf(asn1js.Constructed)
        expect((values[2] as asn1js.Constructed).idBlock.tagNumber).toBe(0)

        const parametersValue = (values[2] as asn1js.Constructed).valueBlock
            .value
        expect(parametersValue.length).toBe(1)
        expect(parametersValue[0]).toBeInstanceOf(asn1js.ObjectIdentifier)
        expect(
            (
                parametersValue[0] as asn1js.ObjectIdentifier
            ).valueBlock.toString(),
        ).toBe(OIDs.CURVES.SECP256R1)

        // PublicKey [1]
        expect(values[3]).toBeInstanceOf(asn1js.Constructed)
        expect((values[3] as asn1js.Constructed).idBlock.tagNumber).toBe(1)

        const publicKeyValue = (values[3] as asn1js.Constructed).valueBlock
            .value
        expect(publicKeyValue.length).toBe(1)
        expect(publicKeyValue[0]).toBeInstanceOf(asn1js.BitString)
    })

    test('toAsn1 correctly encodes ECPrivateKey with only required fields', () => {
        const ecPrivKey = new ECPrivateKey({
            privateKey: privateKeyBytes,
        })

        const asn1 = ecPrivKey.toAsn1()

        // Should be a SEQUENCE
        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const values = (asn1 as asn1js.Sequence).valueBlock.value

        // Should have only 2 elements: version, privateKey
        expect(values.length).toBe(2)

        // Version
        expect(values[0]).toBeInstanceOf(asn1js.Integer)
        expect((values[0] as asn1js.Integer).valueBlock.valueDec).toBe(1)

        // PrivateKey
        expect(values[1]).toBeInstanceOf(asn1js.OctetString)
        expect(
            new Uint8Array(
                (values[1] as asn1js.OctetString).valueBlock.valueHexView,
            ),
        ).toEqual(privateKeyBytes)
    })

    test('fromAsn1 correctly decodes ECPrivateKey with all fields', () => {
        // Create ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                new asn1js.OctetString({ valueHex: privateKeyBytes }),
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [
                        new asn1js.ObjectIdentifier({
                            value: OIDs.CURVES.SECP256R1,
                        }),
                    ],
                }),
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    value: [new asn1js.BitString({ valueHex: publicKeyBytes })],
                }),
            ],
        })

        const ecPrivKey = ECPrivateKey.fromAsn1(asn1)

        expect(ecPrivKey.version).toBe(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toBe(OIDs.CURVES.SECP256R1)
        expect(ecPrivKey.publicKey).toEqual(publicKeyBytes)
    })

    test('fromAsn1 correctly decodes ECPrivateKey with only required fields', () => {
        // Create ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                new asn1js.OctetString({ valueHex: privateKeyBytes }),
            ],
        })

        const ecPrivKey = ECPrivateKey.fromAsn1(asn1)

        expect(ecPrivKey.version).toBe(1)
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

        expect(decoded.version).toBe(original.version)
        expect(decoded.privateKey).toEqual(original.privateKey)
        expect(decoded.namedCurve).toBe(original.namedCurve)
        expect(decoded.publicKey).toEqual(original.publicKey)
    })

    test('forCurve static method creates correctly configured ECPrivateKey', () => {
        const ecPrivKey = ECPrivateKey.forCurve(
            OIDs.CURVES.SECP256K1,
            privateKeyBytes,
            publicKeyBytes,
        )

        expect(ecPrivKey.version).toBe(1)
        expect(ecPrivKey.privateKey).toEqual(privateKeyBytes)
        expect(ecPrivKey.namedCurve).toBe(OIDs.CURVES.SECP256K1)
        expect(ecPrivKey.publicKey).toEqual(publicKeyBytes)
    })

    test('fromAsn1 throws error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 1 })

        expect(() => ECPrivateKey.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for invalid version', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 2 }), // Invalid version
                new asn1js.OctetString({ valueHex: privateKeyBytes }),
            ],
        })

        expect(() => ECPrivateKey.fromAsn1(asn1)).toThrow(
            'Invalid EC private key version: expected 1, got 2',
        )
    })
})
