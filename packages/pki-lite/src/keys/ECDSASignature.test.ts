import { describe, expect, test } from 'vitest'
import { ECDSASignature } from './ECDSASignature.js'
import * as asn1js from 'asn1js'

describe('ECDSASignature', () => {
    // Sample r and s values for testing
    // Using typical P-256 signature component sizes (32 bytes each)
    const r = new Uint8Array([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ])

    // s value with high bit set (will need padding for ASN.1)
    const s = new Uint8Array([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ])

    // Sample with high bit set (needs padding for ASN.1)
    const rHighBit = new Uint8Array([
        0x81, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ])

    // Create an s value with high bit clear (won't need padding)
    const sNoPad = new Uint8Array([
        0x7e, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ])

    test('constructor creates a valid ECDSASignature', () => {
        const signature = new ECDSASignature({ r, s })

        expect(signature.r.bytes).toEqual(r)
        expect(signature.s.bytes).toEqual(s)
    })

    test('toAsn1 creates correct ASN.1 structure with proper padding', () => {
        // Use values that don't need padding for this test
        const signature = new ECDSASignature({ r, s: sNoPad })
        const asn1 = signature.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // Need to cast to 'any' due to type limitations in asn1js
        const values = (asn1 as any).valueBlock.value
        expect(values.length).toEqual(2)

        // Check r
        expect(values[0]).toBeInstanceOf(asn1js.Integer)
        const rBlock = (values[0] as any).valueBlock
        expect(
            new Uint8Array(rBlock.valueHexView || rBlock.valueBeforeDecodeView),
        ).toEqual(r)

        // Check s - should not be padded since high bit is clear
        expect(values[1]).toBeInstanceOf(asn1js.Integer)
        const sBlock = (values[1] as any).valueBlock
        expect(
            new Uint8Array(sBlock.valueHexView || sBlock.valueBeforeDecodeView),
        ).toEqual(sNoPad)
    })

    test('toAsn1 properly handles high bit padding', () => {
        const signature = new ECDSASignature({ r: rHighBit, s })
        const asn1 = signature.toAsn1()

        // Need to cast to 'any' due to type limitations in asn1js
        const values = (asn1 as any).valueBlock.value

        // The Integer class should have already applied padding to its bytes
        // The ASN.1 representation should include the padding
        const rBlock = (values[0] as any).valueBlock
        const rValue = new Uint8Array(
            rBlock.valueHexView || rBlock.valueBeforeDecodeView,
        )

        // First byte should be 0x00 (padding) since rHighBit has high bit set
        expect(rValue[0]).toEqual(0x00) // Padding byte
        expect(rValue[1]).toEqual(0x81) // Original first byte

        // The s value should also be padded since its high bit is set
        const sBlock = (values[1] as any).valueBlock
        const sValue = new Uint8Array(
            sBlock.valueHexView || sBlock.valueBeforeDecodeView,
        )

        expect(sValue[0]).toEqual(0x00) // Padding byte
        expect(sValue[1]).toEqual(0xfe) // Original first byte
    })

    test('fromAsn1 parses ASN.1 structure correctly', () => {
        // Create an ASN.1 structure with padded s value (since high bit is set)
        const paddedS = new Uint8Array(s.length + 1)
        paddedS[0] = 0x00
        paddedS.set(s, 1)

        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ valueHex: r }),
                new asn1js.Integer({ valueHex: paddedS }),
            ],
        })

        const signature = ECDSASignature.fromAsn1(asn1)

        expect(signature.r.bytes).toEqual(r)

        // The s value should retain the padding for consistency in the Integer class
        // This is different from the original implementation which stripped padding
        const expectedS = new Uint8Array(s.length + 1)
        expectedS[0] = 0x00
        expectedS.set(s, 1)
        expect(signature.s.bytes).toEqual(expectedS)
    })

    test('toDer/fromDer roundtrip works correctly', () => {
        // Use values that don't need padding to simplify the test
        const originalSignature = new ECDSASignature({ r, s: sNoPad })
        const der = originalSignature.toDer()
        const parsedSignature = ECDSASignature.fromDer(der)

        expect(parsedSignature.r.bytes).toEqual(originalSignature.r.bytes)
        expect(parsedSignature.s.bytes).toEqual(originalSignature.s.bytes)
    })

    test('toRaw produces correct concatenated format', () => {
        const signature = new ECDSASignature({ r, s })
        const raw = signature.toRaw()

        // Raw should be r concatenated with s
        expect(raw.length).toEqual(r.length + s.length)
        expect(raw.slice(0, r.length)).toEqual(r)
        expect(raw.slice(r.length)).toEqual(s)
    })

    test('fromRaw correctly parses concatenated format', () => {
        // Create raw signature (r || s)
        const raw = new Uint8Array(r.length + s.length)
        raw.set(r, 0)
        raw.set(s, r.length)

        const signature = ECDSASignature.fromRaw(raw)

        expect(signature.r.bytes).toEqual(r)
        expect(signature.s.bytes).toEqual(s)
    })

    test('fromRaw throws error on odd-length input', () => {
        const invalidRaw = new Uint8Array(63) // Odd length

        expect(() => ECDSASignature.fromRaw(invalidRaw)).toThrow(
            'Invalid raw ECDSA signature: length must be even',
        )
    })

    test('fromAsn1 throws on invalid ASN.1 structure', () => {
        // Not a sequence
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => ECDSASignature.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )

        // Wrong number of elements
        const invalidSequence = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 123 })],
        })

        expect(() => ECDSASignature.fromAsn1(invalidSequence)).toThrow(
            'Invalid ASN.1 structure: expected 2 elements',
        )

        // First element not an integer
        const invalidR = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: r }),
                new asn1js.Integer({ valueHex: s }),
            ],
        })

        expect(() => ECDSASignature.fromAsn1(invalidR)).toThrow(
            'Invalid ASN.1 structure: r must be INTEGER',
        )

        // Second element not an integer
        const invalidS = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ valueHex: r }),
                new asn1js.OctetString({ valueHex: s }),
            ],
        })

        expect(() => ECDSASignature.fromAsn1(invalidS)).toThrow(
            'Invalid ASN.1 structure: s must be INTEGER',
        )
    })
})
