import { GCMParameters } from './GCMParameters.js'
import { AlgorithmIdentifier } from './AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { test, expect, describe } from 'vitest'
import { derToAsn1 } from '../core/PkiBase.js'

describe('GCMParameters', () => {
    test('GCMParameters should create and encode parameters with default values', () => {
        // Create a nonce with the recommended 12 octets
        const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        const gcmParams = new GCMParameters({ aesNonce: nonce })

        // Encode to DER
        const der = gcmParams.toDer()

        // Decode back from DER
        const decoded = GCMParameters.fromAsn1(derToAsn1(der))

        // Verify properties
        expect(decoded.aesNonce.bytes).toEqual(nonce)
        expect(decoded.aesICVlen.get()).toEqual(12) // Default value is not encoded
    })

    test('GCMParameters should create and encode parameters with explicit ICV length', () => {
        // Create a nonce with the recommended 12 octets
        const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        const icvLen = 16 // Maximum ICV length
        const gcmParams = new GCMParameters({
            aesNonce: nonce,
            aesICVlen: icvLen,
        })

        // Encode to DER
        const der = gcmParams.toDer()

        // Decode back from DER
        const decoded = GCMParameters.fromAsn1(derToAsn1(der))

        // Verify properties
        expect(decoded.aesNonce.bytes).toEqual(nonce)
        expect(decoded.aesICVlen.get()).toEqual(icvLen)
    })

    test('GCMParameters should work with AlgorithmIdentifier', () => {
        // Create GCM parameters
        const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        const gcmParams = new GCMParameters({ aesNonce: nonce, aesICVlen: 16 })

        // Create algorithm identifier for AES-256-GCM
        const gcmAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.ENCRYPTION.AES_256_GCM,
            parameters: gcmParams.toDer(),
        })

        // Encode to DER
        const der = gcmAlgorithm.toDer()

        // Decode back
        const decoded = AlgorithmIdentifier.fromAsn1(derToAsn1(der))

        // Parse parameters
        const decodedParams = decoded.parameters?.parseAs(GCMParameters)!

        // Verify parameters were preserved
        expect(decodedParams.aesNonce.bytes).toEqual(nonce)
        expect(decodedParams.aesICVlen.get()).toEqual(16)
        expect(decoded.algorithm.toString()).toEqual(
            OIDs.ENCRYPTION.AES_256_GCM,
        )
    })

    test('GCMParameters should accept OctetString as nonce', () => {
        // Create a nonce using OctetString
        const nonceBytes = new Uint8Array([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ])
        const gcmParams = new GCMParameters({
            aesNonce: nonceBytes,
            aesICVlen: 14,
        })

        // Verify properties
        expect(gcmParams.aesNonce.bytes).toEqual(nonceBytes)
        expect(gcmParams.aesICVlen.get()).toEqual(14)
    })

    test('GCMParameters should accept nonces of any length', () => {
        // Non-standard length nonce should still be accepted
        const nonStandardNonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
        const gcmParams = new GCMParameters({ aesNonce: nonStandardNonce })

        expect(gcmParams.aesNonce.bytes).toEqual(nonStandardNonce)
        expect(gcmParams.aesICVlen.get()).toEqual(12) // Default value
    })

    test('GCMParameters should throw on invalid ICV length', () => {
        const validNonce = new Uint8Array([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ])

        // Invalid ICV length (must be one of: 12, 13, 14, 15, 16)
        expect(
            () => new GCMParameters({ aesNonce: validNonce, aesICVlen: 8 }),
        ).toThrow(/ICV length must be one of/)
        expect(
            () => new GCMParameters({ aesNonce: validNonce, aesICVlen: 11 }),
        ).toThrow(/ICV length must be one of/)
        expect(
            () => new GCMParameters({ aesNonce: validNonce, aesICVlen: 17 }),
        ).toThrow(/ICV length must be one of/)
    })
})
