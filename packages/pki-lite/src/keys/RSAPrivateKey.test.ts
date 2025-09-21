import { describe, expect, test } from 'vitest'
import { RSAPrivateKey } from './RSAPrivateKey.js'
import * as asn1js from 'asn1js'

describe('RSAPrivateKey', () => {
    // Sample test data
    const modulus = new Uint8Array([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
    ])

    const publicExponent = new Uint8Array([0x01, 0x00, 0x01]) // 65537

    const privateExponent = new Uint8Array([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x00,
    ])

    const prime1 = new Uint8Array([
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    ])

    const prime2 = new Uint8Array([
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
    ])

    const exponent1 = new Uint8Array([
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
    ])

    const exponent2 = new Uint8Array([
        0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
    ])

    const coefficient = new Uint8Array([
        0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ])

    test('constructor creates a valid RSAPrivateKey', () => {
        const key = new RSAPrivateKey({
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        })

        expect(key.version).toBe(0)
        expect(key.modulus).toEqual(modulus)
        expect(key.publicExponent).toEqual(publicExponent)
        expect(key.privateExponent).toEqual(privateExponent)
        expect(key.prime1).toEqual(prime1)
        expect(key.prime2).toEqual(prime2)
        expect(key.exponent1).toEqual(exponent1)
        expect(key.exponent2).toEqual(exponent2)
        expect(key.coefficient).toEqual(coefficient)
    })

    test('toAsn1 creates correct ASN.1 structure', () => {
        const key = new RSAPrivateKey({
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        })

        const asn1 = key.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const values = (asn1 as any).valueBlock.value
        expect(values.length).toBe(9)

        // Check version
        expect(values[0]).toBeInstanceOf(asn1js.Integer)
        expect((values[0] as any).valueBlock.valueDec).toBe(0)

        // Check other components (using the same method as in the fromAsn1 method)
        const components = [
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        ]

        for (let i = 0; i < components.length; i++) {
            expect(values[i + 1]).toBeInstanceOf(asn1js.Integer)
            const valueBlock = (values[i + 1] as any).valueBlock
            const actualValue = new Uint8Array(
                valueBlock.valueHexView || valueBlock.valueBeforeDecodeView,
            )
            expect(actualValue).toEqual(components[i])
        }
    })

    test('fromAsn1 parses ASN.1 structure correctly', () => {
        // Create an ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Integer({ valueHex: modulus }),
                new asn1js.Integer({ valueHex: publicExponent }),
                new asn1js.Integer({ valueHex: privateExponent }),
                new asn1js.Integer({ valueHex: prime1 }),
                new asn1js.Integer({ valueHex: prime2 }),
                new asn1js.Integer({ valueHex: exponent1 }),
                new asn1js.Integer({ valueHex: exponent2 }),
                new asn1js.Integer({ valueHex: coefficient }),
            ],
        })

        const key = RSAPrivateKey.fromAsn1(asn1)

        expect(key.version).toBe(0)
        expect(key.modulus).toEqual(modulus)
        expect(key.publicExponent).toEqual(publicExponent)
        expect(key.privateExponent).toEqual(privateExponent)
        expect(key.prime1).toEqual(prime1)
        expect(key.prime2).toEqual(prime2)
        expect(key.exponent1).toEqual(exponent1)
        expect(key.exponent2).toEqual(exponent2)
        expect(key.coefficient).toEqual(coefficient)
    })

    test('toDer/fromDer roundtrip works correctly', () => {
        const key = new RSAPrivateKey({
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        })

        const der = key.toDer()
        const parsedKey = RSAPrivateKey.fromDer(der)

        expect(parsedKey.version).toBe(key.version)
        expect(parsedKey.modulus).toEqual(key.modulus)
        expect(parsedKey.publicExponent).toEqual(key.publicExponent)
        expect(parsedKey.privateExponent).toEqual(key.privateExponent)
        expect(parsedKey.prime1).toEqual(key.prime1)
        expect(parsedKey.prime2).toEqual(key.prime2)
        expect(parsedKey.exponent1).toEqual(key.exponent1)
        expect(parsedKey.exponent2).toEqual(key.exponent2)
        expect(parsedKey.coefficient).toEqual(key.coefficient)
    })

    test('toPublicKey extracts the components correctly', () => {
        const key = new RSAPrivateKey({
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        })

        const publicKeyData = key.toPublicKey()

        expect(publicKeyData.modulus).toEqual(modulus)
        expect(publicKeyData.publicExponent).toEqual(publicExponent)
    })

    test('fromAsn1 throws on invalid ASN.1 structure', () => {
        // Not a sequence
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => RSAPrivateKey.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Not enough elements
        const invalidSequence = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Integer({ valueHex: modulus }),
            ],
        })

        expect(() => RSAPrivateKey.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected at least 9 elements',
        )

        // Version not an integer
        const invalidVersion = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([0]) }),
                new asn1js.Integer({ valueHex: modulus }),
                new asn1js.Integer({ valueHex: publicExponent }),
                new asn1js.Integer({ valueHex: privateExponent }),
                new asn1js.Integer({ valueHex: prime1 }),
                new asn1js.Integer({ valueHex: prime2 }),
                new asn1js.Integer({ valueHex: exponent1 }),
                new asn1js.Integer({ valueHex: exponent2 }),
                new asn1js.Integer({ valueHex: coefficient }),
            ],
        })

        expect(() => RSAPrivateKey.fromAsn1(invalidVersion)).toThrow(
            'Invalid ASN.1 structure: version must be INTEGER',
        )

        // One of the components not an integer
        const invalidComponent = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Integer({ valueHex: modulus }),
                new asn1js.Integer({ valueHex: publicExponent }),
                new asn1js.OctetString({ valueHex: privateExponent }), // This should be an Integer
                new asn1js.Integer({ valueHex: prime1 }),
                new asn1js.Integer({ valueHex: prime2 }),
                new asn1js.Integer({ valueHex: exponent1 }),
                new asn1js.Integer({ valueHex: exponent2 }),
                new asn1js.Integer({ valueHex: coefficient }),
            ],
        })

        expect(() => RSAPrivateKey.fromAsn1(invalidComponent)).toThrow(
            'Invalid ASN.1 structure: element at index 3 must be INTEGER',
        )
    })
})
