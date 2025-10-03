import { describe, expect, test } from 'vitest'
import { padUint8Array, hexToUint8Array, uint8ArrayToHex } from './utils.js'

describe('padUint8Array', () => {
    test('should pad array with zeros on the left', () => {
        const input = new Uint8Array([1, 2, 3])
        const result = padUint8Array(input, 5)

        expect(result).toEqual(new Uint8Array([0, 0, 1, 2, 3]))
        expect(result.length).toEqual(5)
    })

    test('should return original array if already at target length', () => {
        const input = new Uint8Array([1, 2, 3])
        const result = padUint8Array(input, 3)

        expect(result).toEqual(input)
        expect(result.length).toEqual(3)
    })

    test('should return original array if longer than target length', () => {
        const input = new Uint8Array([1, 2, 3, 4, 5])
        const result = padUint8Array(input, 3)

        expect(result).toEqual(input)
        expect(result.length).toEqual(5)
    })

    test('should handle empty array', () => {
        const input = new Uint8Array([])
        const result = padUint8Array(input, 3)

        expect(result).toEqual(new Uint8Array([0, 0, 0]))
        expect(result.length).toEqual(3)
    })

    test('should handle zero target length', () => {
        const input = new Uint8Array([1, 2, 3])
        const result = padUint8Array(input, 0)

        expect(result).toEqual(input)
        expect(result.length).toEqual(3)
    })

    test('should pad to larger lengths correctly', () => {
        const input = new Uint8Array([0xff])
        const result = padUint8Array(input, 10)

        const expected = new Uint8Array(10)
        expected[9] = 0xff // Last position should have the original value

        expect(result).toEqual(expected)
        expect(result.length).toEqual(10)
    })

    test('should preserve original array bytes', () => {
        const input = new Uint8Array([0x12, 0x34, 0x56, 0x78])
        const result = padUint8Array(input, 8)

        expect(result.slice(-4)).toEqual(input) // Last 4 bytes should match original
        expect(result.slice(0, 4)).toEqual(new Uint8Array([0, 0, 0, 0])) // First 4 should be zeros
    })
})

describe('hexToUint8Array', () => {
    test('should convert basic hex string to Uint8Array<ArrayBuffer>', () => {
        const hex = '123456'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0x12, 0x34, 0x56]))
    })

    test('should handle hex string with 0x prefix', () => {
        const hex = '0x123456'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0x12, 0x34, 0x56]))
    })

    test('should handle odd-length hex strings by padding with leading zero', () => {
        const hex = '12345'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0x01, 0x23, 0x45]))
    })

    test('should handle empty hex string', () => {
        const hex = ''
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([]))
    })

    test('should handle single hex character', () => {
        const hex = 'a'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0x0a]))
    })

    test('should handle hex string with lowercase letters', () => {
        const hex = 'abcdef'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0xab, 0xcd, 0xef]))
    })

    test('should handle hex string with uppercase letters', () => {
        const hex = 'ABCDEF'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0xab, 0xcd, 0xef]))
    })

    test('should handle mixed case hex string', () => {
        const hex = 'aAbBcCdDeEfF'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(
            new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        )
    })

    test('should handle all zero hex string', () => {
        const hex = '000000'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0x00, 0x00, 0x00]))
    })

    test('should handle all ff hex string', () => {
        const hex = 'ffffff'
        const result = hexToUint8Array(hex)

        expect(result).toEqual(new Uint8Array([0xff, 0xff, 0xff]))
    })
})

describe('uint8ArrayToHex', () => {
    test('should convert Uint8Array<ArrayBuffer> to hex string without prefix', () => {
        const bytes = new Uint8Array([0x12, 0x34, 0x56])
        const result = uint8ArrayToHex(bytes)

        expect(result).toEqual('123456')
    })

    test('should convert Uint8Array<ArrayBuffer> to hex string with prefix', () => {
        const bytes = new Uint8Array([0x12, 0x34, 0x56])
        const result = uint8ArrayToHex(bytes, true)

        expect(result).toEqual('0x123456')
    })

    test('should handle empty Uint8Array<ArrayBuffer>', () => {
        const bytes = new Uint8Array([])
        const result = uint8ArrayToHex(bytes)

        expect(result).toEqual('')
    })

    test('should handle empty Uint8Array<ArrayBuffer> with prefix', () => {
        const bytes = new Uint8Array([])
        const result = uint8ArrayToHex(bytes, true)

        expect(result).toEqual('0x')
    })

    test('should handle single byte', () => {
        const bytes = new Uint8Array([0xab])
        const result = uint8ArrayToHex(bytes)

        expect(result).toEqual('ab')
    })

    test('should pad single digit hex values with zero', () => {
        const bytes = new Uint8Array([0x01, 0x02, 0x0f])
        const result = uint8ArrayToHex(bytes)

        expect(result).toEqual('01020f')
    })

    test('should handle all zero bytes', () => {
        const bytes = new Uint8Array([0x00, 0x00, 0x00])
        const result = uint8ArrayToHex(bytes)

        expect(result).toEqual('000000')
    })

    test('should handle all ff bytes', () => {
        const bytes = new Uint8Array([0xff, 0xff, 0xff])
        const result = uint8ArrayToHex(bytes)

        expect(result).toEqual('ffffff')
    })

    test('should handle large arrays', () => {
        const bytes = new Uint8Array(256)
        for (let i = 0; i < 256; i++) {
            bytes[i] = i
        }
        const result = uint8ArrayToHex(bytes)

        expect(result.length).toEqual(512) // 256 bytes * 2 hex chars per byte
        expect(result.startsWith('000102')).toEqual(true)
        expect(result.endsWith('fdfeff')).toEqual(true)
    })
})

describe('round-trip conversion', () => {
    test('hex -> Uint8Array<ArrayBuffer> -> hex should preserve data', () => {
        const testCases = [
            '123456',
            'abcdef',
            'ABCDEF',
            '000000',
            'ffffff',
            '01020304050607080910',
            'a',
            'ab',
            '',
        ]

        for (const hex of testCases) {
            const bytes = hexToUint8Array(hex)
            const backToHex = uint8ArrayToHex(bytes)

            // For odd-length inputs, we expect a leading zero to be added
            const expectedHex =
                hex.length % 2 === 0
                    ? hex.toLowerCase()
                    : ('0' + hex).toLowerCase()
            expect(backToHex).toEqual(expectedHex)
        }
    })

    test('Uint8Array<ArrayBuffer> -> hex -> Uint8Array<ArrayBuffer> should preserve data', () => {
        const testCases = [
            new Uint8Array([]),
            new Uint8Array([0x00]),
            new Uint8Array([0xff]),
            new Uint8Array([0x12, 0x34, 0x56]),
            new Uint8Array([0x00, 0x01, 0x02, 0x03]),
            new Uint8Array([0xab, 0xcd, 0xef]),
        ]

        for (const bytes of testCases) {
            const hex = uint8ArrayToHex(bytes)
            const backToBytes = hexToUint8Array(hex)

            expect(backToBytes).toEqual(bytes)
        }
    })
})
