import { describe, expect, test } from 'vitest'
import { ECPublicKey } from './ECPublicKey.js'
import { asn1js } from '../core/PkiBase.js'

describe('ECPublicKey', () => {
    // Sample X and Y coordinates (32 bytes each for P-256)
    const xCoord = new Uint8Array([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ])

    const yCoord = new Uint8Array([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ])

    // Sample uncompressed key (0x04 || x || y)
    const publicKey = new Uint8Array(1 + xCoord.length + yCoord.length)
    publicKey[0] = 0x04 // Uncompressed point format
    publicKey.set(xCoord, 1)
    publicKey.set(yCoord, 1 + xCoord.length)

    test('fromRaw creates valid ECPublicKey', () => {
        const key = ECPublicKey.fromRaw(publicKey)
        expect(key.bytes).toEqual(publicKey)
    })

    test('toRaw creates valid raw representation', () => {
        const key = ECPublicKey.fromRaw(publicKey)
        const raw = key.toRaw()
        expect(raw).toEqual(publicKey)
    })

    test('fromCoordinates creates valid ECPublicKey', () => {
        const key = ECPublicKey.fromCoordinates(xCoord, yCoord)

        expect(key.bytes).toEqual(publicKey)
    })

    test('getCoordinates extracts coordinates correctly', () => {
        const key = new ECPublicKey({ value: publicKey })
        const coords = key.getCoordinates()

        expect(coords.x).toEqual(xCoord)
        expect(coords.y).toEqual(yCoord)
    })

    test('throws an error if invalid point format', () => {
        // Create a key with invalid format (not starting with 0x04)
        const invalidPublicKey = new Uint8Array(65)
        invalidPublicKey[0] = 0x03 // Compressed format instead of uncompressed
        invalidPublicKey.set(xCoord, 1)
        expect(() => new ECPublicKey({ value: invalidPublicKey })).toThrow(
            'Invalid ECPublicKey: expected uncompressed point format (0x04)',
        )
    })
})
