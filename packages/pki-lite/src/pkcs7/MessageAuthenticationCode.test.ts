import { describe, it, expect } from 'vitest'
import { asn1js } from '../core/PkiBase.js'
import { MessageAuthenticationCode } from './MessageAuthenticationCode.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

describe('MessageAuthenticationCode', () => {
    // Sample MAC bytes (simulating a SHA-256 MAC)
    const macBytes = new Uint8Array([
        0x48, 0x1f, 0x6c, 0xc0, 0x21, 0x5c, 0x9f, 0x96, 0x41, 0x84, 0x2e, 0x8c,
        0x97, 0x46, 0xfe, 0xc8, 0x87, 0x5d, 0x0a, 0x5c, 0x8e, 0x43, 0x4f, 0x7b,
        0x77, 0x3f, 0x89, 0x23, 0xd4, 0x6a, 0x9f, 0x2b,
    ])

    it('should create MessageAuthenticationCode from bytes', () => {
        const mac = new MessageAuthenticationCode({ bytes: macBytes })

        expect(mac).toBeInstanceOf(MessageAuthenticationCode)
        expect(mac.bytes).toEqual(macBytes)
    })

    it('should create MessageAuthenticationCode from string', () => {
        const macString = 'test-mac-value'
        const mac = new MessageAuthenticationCode({ bytes: macString })

        expect(mac).toBeInstanceOf(MessageAuthenticationCode)
        const expectedBytes = new TextEncoder().encode(macString)
        expect(mac.bytes).toEqual(expectedBytes)
    })

    it('should create MessageAuthenticationCode from another MessageAuthenticationCode', () => {
        const original = new MessageAuthenticationCode({ bytes: macBytes })
        const copy = new MessageAuthenticationCode({ bytes: original })

        expect(copy).toBeInstanceOf(MessageAuthenticationCode)
        expect(copy.bytes).toEqual(original.bytes)
        expect(copy.bytes).toEqual(macBytes)
    })

    it('should convert to ASN.1 correctly', () => {
        const mac = new MessageAuthenticationCode({ bytes: macBytes })
        const asn1 = mac.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.OctetString)

        // Check the value is preserved
        const valueHex = new Uint8Array((asn1 as any).valueBlock.valueHexView)
        expect(valueHex).toEqual(macBytes)
    })

    it('should parse from valid ASN.1 OctetString', () => {
        // Create an ASN.1 OctetString
        const asn1 = new asn1js.OctetString({ valueHex: macBytes })

        const mac = MessageAuthenticationCode.fromAsn1(asn1)

        expect(mac).toBeInstanceOf(MessageAuthenticationCode)
        expect(mac.bytes).toEqual(macBytes)
    })

    it('should throw error when parsing invalid ASN.1 structure', () => {
        // Create an ASN.1 Integer instead of OctetString
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => {
            MessageAuthenticationCode.fromAsn1(invalidAsn1)
        }).toThrow(Asn1ParseError)

        expect(() => {
            MessageAuthenticationCode.fromAsn1(invalidAsn1)
        }).toThrow(
            'Invalid ASN.1 structure: expected OctetString for MessageAuthenticationCode',
        )
    })

    it('should handle empty MAC bytes', () => {
        const emptyBytes = new Uint8Array([])
        const mac = new MessageAuthenticationCode({ bytes: emptyBytes })

        expect(mac.bytes).toEqual(emptyBytes)
        expect(mac.bytes.length).toEqual(0)

        const asn1 = mac.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.OctetString)
    })

    it('should handle round-trip conversion (to ASN.1 and back)', () => {
        const originalMac = new MessageAuthenticationCode({ bytes: macBytes })

        // Convert to ASN.1
        const asn1 = originalMac.toAsn1()

        // Convert back from ASN.1
        const reconstructedMac = MessageAuthenticationCode.fromAsn1(asn1)

        expect(reconstructedMac.bytes).toEqual(originalMac.bytes)
        expect(reconstructedMac.bytes).toEqual(macBytes)
    })

    it('should inherit OctetString functionality', () => {
        const mac = new MessageAuthenticationCode({ bytes: macBytes })

        // Should have access to parent methods
        expect(typeof mac.toString).toBe('function')
        expect(typeof mac.toDer).toBe('function')
        expect(typeof mac.toPem).toBe('function')
    })

    it('MessageAuthenticationCode toString snapshot', () => {
        const mac = new MessageAuthenticationCode({ bytes: macBytes })
        expect(mac.toString()).toMatchInlineSnapshot(
            `"[MessageAuthenticationCode] OCTET STRING : 481f6cc0215c9f9641842e8c9746fec8875d0a5c8e434f7b773f8923d46a9f2b"`,
        )
    })

    it('MessageAuthenticationCode toString snapshot empty', () => {
        const emptyMac = new MessageAuthenticationCode({
            bytes: new Uint8Array([]),
        })
        expect(emptyMac.toString()).toMatchInlineSnapshot(
            `"[MessageAuthenticationCode] OCTET STRING : "`,
        )
    })

    it('should handle various MAC sizes', () => {
        // Test different common MAC sizes
        const testCases = [
            { size: 16, name: 'MD5/HMAC-MD5' }, // 128 bits
            { size: 20, name: 'SHA-1/HMAC-SHA-1' }, // 160 bits
            { size: 32, name: 'SHA-256/HMAC-SHA-256' }, // 256 bits
            { size: 48, name: 'SHA-384/HMAC-SHA-384' }, // 384 bits
            { size: 64, name: 'SHA-512/HMAC-SHA-512' }, // 512 bits
        ]

        testCases.forEach(({ size, name }) => {
            const testBytes = new Uint8Array(size).fill(0xab)
            const mac = new MessageAuthenticationCode({ bytes: testBytes })

            expect(mac.bytes).toEqual(testBytes)
            expect(mac.bytes.length).toEqual(size)

            // Verify ASN.1 conversion works
            const asn1 = mac.toAsn1()
            expect(asn1).toBeInstanceOf(asn1js.OctetString)

            // Verify round-trip
            const reconstructed = MessageAuthenticationCode.fromAsn1(asn1)
            expect(reconstructed.bytes).toEqual(testBytes)
        })
    })
})
