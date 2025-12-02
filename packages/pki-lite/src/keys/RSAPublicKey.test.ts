import { describe, expect, test } from 'vitest'
import { RSAPublicKey } from './RSAPublicKey.js'
import { asn1js } from '../core/PkiBase.js'

describe('RSAPublicKey', () => {
    // Sample test data
    const modulus = new Uint8Array([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
    ])

    const publicExponent = new Uint8Array([0x01, 0x00, 0x01]) // 65537

    test('constructor creates a valid RSAPublicKey', () => {
        const key = new RSAPublicKey({ modulus, publicExponent })

        expect(key.modulus).toEqual(modulus)
        expect(key.publicExponent).toEqual(publicExponent)
    })

    test('toAsn1 creates correct ASN.1 structure', () => {
        const key = new RSAPublicKey({ modulus, publicExponent })
        const asn1 = key.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        const values = (asn1 as any).valueBlock.value
        expect(values.length).toEqual(2)

        // Check modulus
        expect(values[0]).toBeInstanceOf(asn1js.Integer)
        const modulusBlock = values[0].valueBlock as any
        expect(
            new Uint8Array(
                modulusBlock.valueHexView || modulusBlock.valueBeforeDecodeView,
            ),
        ).toEqual(modulus)

        // Check publicExponent
        expect(values[1]).toBeInstanceOf(asn1js.Integer)
        const exponentBlock = values[1].valueBlock as any
        expect(
            new Uint8Array(
                exponentBlock.valueHexView ||
                    exponentBlock.valueBeforeDecodeView,
            ),
        ).toEqual(publicExponent)
    })

    test('fromAsn1 parses ASN.1 structure correctly', () => {
        // Create an ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ valueHex: modulus }),
                new asn1js.Integer({ valueHex: publicExponent }),
            ],
        })

        const key = RSAPublicKey.fromAsn1(asn1)

        expect(key.modulus).toEqual(modulus)
        expect(key.publicExponent).toEqual(publicExponent)
    })

    test('toDer/fromDer roundtrip works correctly', () => {
        const originalKey = new RSAPublicKey({ modulus, publicExponent })
        const der = originalKey.toDer()
        const parsedKey = RSAPublicKey.fromDer(der)

        expect(parsedKey.modulus).toEqual(originalKey.modulus)
        expect(parsedKey.publicExponent).toEqual(originalKey.publicExponent)
    })

    test('fromAsn1 throws on invalid ASN.1 structure', () => {
        // Not a sequence
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => RSAPublicKey.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Wrong number of elements
        const invalidSequence = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 123 })],
        })

        expect(() => RSAPublicKey.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 2 elements',
        )

        // First element not an integer
        const invalidModulus = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: modulus }),
                new asn1js.Integer({ valueHex: publicExponent }),
            ],
        })

        expect(() => RSAPublicKey.fromAsn1(invalidModulus)).toThrow(
            'Invalid ASN.1 structure: modulus must be INTEGER',
        )

        // Second element not an integer
        const invalidExponent = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ valueHex: modulus }),
                new asn1js.OctetString({ valueHex: publicExponent }),
            ],
        })

        expect(() => RSAPublicKey.fromAsn1(invalidExponent)).toThrow(
            'Invalid ASN.1 structure: publicExponent must be INTEGER',
        )
    })
})
