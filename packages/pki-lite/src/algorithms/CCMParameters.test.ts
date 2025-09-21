import { CCMParameters } from './CCMParameters.js'
import { AlgorithmIdentifier } from './AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { OctetString } from '../asn1/OctetString.js'
import { test, expect, describe } from 'vitest'
import { derToAsn1 } from '../core/PkiBase.js'

describe('CCMParameters', () => {
    test('CCMParameters should create and encode parameters with default values', () => {
        // Create a nonce with 7 octets (minimum allowed length)
        const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7])
        const ccmParams = new CCMParameters({ aesNonce: nonce })

        // Encode to DER
        const der = ccmParams.toDer()

        // Decode back from DER
        const decoded = CCMParameters.fromAsn1(derToAsn1(der))

        // Verify properties
        expect(decoded.aesNonce.bytes).toEqual(nonce)
        expect(decoded.aesICVlen.get()).toEqual(12) // Default value is not encoded
    })

    test('CCMParameters should create and encode parameters with explicit ICV length', () => {
        // Create a nonce with 13 octets (maximum allowed length)
        const nonce = new Uint8Array([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        ])
        const icvLen = 16 // Maximum ICV length
        const ccmParams = new CCMParameters({
            aesNonce: nonce,
            aesICVlen: icvLen,
        })

        // Encode to DER
        const der = ccmParams.toDer()

        // Decode back from DER
        const decoded = CCMParameters.fromAsn1(derToAsn1(der))

        // Verify properties
        expect(decoded.aesNonce.bytes).toEqual(nonce)
        expect(decoded.aesICVlen.get()).toEqual(icvLen)
    })

    test('CCMParameters should work with AlgorithmIdentifier', () => {
        // Create CCM parameters
        const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])
        const ccmParams = new CCMParameters({ aesNonce: nonce, aesICVlen: 10 })

        // Create algorithm identifier for AES-128-CCM
        const ccmAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.ENCRYPTION.AES_128_CCM,
            parameters: ccmParams,
        })

        // Encode to DER
        const der = ccmAlgorithm.toDer()

        // Decode back
        const decoded = AlgorithmIdentifier.fromAsn1(derToAsn1(der))

        // Parse parameters
        const decodedParams = decoded.parameters?.parseAs(CCMParameters)!

        // Verify parameters were preserved
        expect(decodedParams.aesNonce.bytes).toEqual(nonce)
        expect(decodedParams.aesICVlen.get()).toEqual(10)
        expect(decoded.algorithm.toString()).toEqual(
            OIDs.ENCRYPTION.AES_128_CCM,
        )
    })

    test('CCMParameters should accept OctetString as nonce', () => {
        // Create a nonce using OctetString
        const nonceBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])
        const nonceString = new OctetString({ bytes: nonceBytes })
        const ccmParams = new CCMParameters({
            aesNonce: nonceString,
            aesICVlen: 8,
        })

        // Verify properties
        expect(ccmParams.aesNonce.bytes).toEqual(nonceBytes)
        expect(ccmParams.aesICVlen.get()).toEqual(8)
    })

    test('CCMParameters should throw on invalid nonce length', () => {
        // Too short (less than 7 octets)
        const tooShort = new Uint8Array([1, 2, 3, 4, 5, 6])
        expect(() => new CCMParameters({ aesNonce: tooShort })).toThrow(
            /must be between 7 and 13 octets/,
        )

        // Too long (more than 13 octets)
        const tooLong = new Uint8Array([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        ])
        expect(() => new CCMParameters({ aesNonce: tooLong })).toThrow(
            /must be between 7 and 13 octets/,
        )
    })

    test('CCMParameters should throw on invalid ICV length', () => {
        const validNonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7])

        // Invalid ICV length (must be one of: 4, 6, 8, 10, 12, 14, 16)
        expect(
            () => new CCMParameters({ aesNonce: validNonce, aesICVlen: 5 }),
        ).toThrow(/ICV length must be one of/)
        expect(
            () => new CCMParameters({ aesNonce: validNonce, aesICVlen: 7 }),
        ).toThrow(/ICV length must be one of/)
        expect(
            () => new CCMParameters({ aesNonce: validNonce, aesICVlen: 18 }),
        ).toThrow(/ICV length must be one of/)
    })
})
