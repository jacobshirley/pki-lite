/**
 * Test vectors for MD5 from RFC 1321
 */

import { describe, it, expect } from 'vitest'
import { md5 } from '../../src/crypto/md5.js'

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

describe('MD5', () => {
    // Test vectors from RFC 1321
    const testVectors: Array<[string, string]> = [
        ['', 'd41d8cd98f00b204e9800998ecf8427e'],
        ['a', '0cc175b9c0f1b6a831c399e269772661'],
        ['abc', '900150983cd24fb0d6963f7d28e17f72'],
        ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
        ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
        [
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            'd174ab98d277d9f5a5611c2c9f419d9f',
        ],
        [
            '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
            '57edf4a22be3c955ac49da2e2107b67a',
        ],
    ]

    testVectors.forEach(([input, expected]) => {
        it(`should hash "${input.length > 50 ? input.substring(0, 50) + '...' : input}" correctly`, () => {
            const data = new TextEncoder().encode(input)
            const hash = md5(data)
            const hex = bytesToHex(hash)
            expect(hex).toBe(expected)
        })
    })

    it('should produce consistent results', () => {
        const data = new TextEncoder().encode('test data')
        const hash1 = md5(data)
        const hash2 = md5(data)
        expect(bytesToHex(hash1)).toBe(bytesToHex(hash2))
    })

    it('should return 16 bytes', () => {
        const data = new TextEncoder().encode('any data')
        const hash = md5(data)
        expect(hash.length).toBe(16)
    })

    it('should handle empty input', () => {
        const data = new Uint8Array(0)
        const hash = md5(data)
        expect(bytesToHex(hash)).toBe('d41d8cd98f00b204e9800998ecf8427e')
    })

    it('should handle large input', () => {
        // Test with 1MB of data
        const largeData = new Uint8Array(1024 * 1024)
        for (let i = 0; i < largeData.length; i++) {
            largeData[i] = i % 256
        }
        const hash = md5(largeData)
        expect(hash.length).toBe(16)
        // Just verify it doesn't throw and produces valid output
        expect(bytesToHex(hash)).toMatch(/^[0-9a-f]{32}$/)
    })
})
