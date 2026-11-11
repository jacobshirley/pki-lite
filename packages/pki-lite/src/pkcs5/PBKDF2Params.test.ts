import { describe, test, expect } from 'vitest'
import { PBKDF2Params } from './PBKDF2Params.js'
import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { der, UniversalTag } from '../core/PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'

describe('PBKDF2Params', () => {
    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const iterationCount = 2000
    const keyLength = 32
    const prf = new DigestAlgorithmIdentifier({
        algorithm: OIDs.HASH.HMAC_SHA256,
    })

    test('constructor should set properties with Uint8Array<ArrayBuffer> salt', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
            keyLength,
            prf,
        })

        expect(params.salt).toBeInstanceOf(OctetString)
        expect(params.iterationCount).toEqual(iterationCount)
        expect(params.keyLength).toEqual(keyLength)
        expect(params.prf.algorithm.value).toEqual(OIDs.HASH.HMAC_SHA256)
    })

    test('constructor should set properties with OctetString salt', () => {
        const octetStringSalt = new OctetString({ bytes: salt })
        const params = new PBKDF2Params({
            salt: octetStringSalt,
            iterationCount,
            keyLength,
            prf,
        })

        expect(params.salt).toEqual(octetStringSalt)
        expect(params.iterationCount).toEqual(iterationCount)
        expect(params.keyLength).toEqual(keyLength)
        expect(params.prf.algorithm.value).toEqual(OIDs.HASH.HMAC_SHA256)
    })

    test('constructor should set properties with AlgorithmIdentifier salt', () => {
        const algIdSalt = new AlgorithmIdentifier({
            algorithm: OIDs.PKCS5.PBKDF2,
        })

        const params = new PBKDF2Params({
            salt: algIdSalt,
            iterationCount,
            keyLength,
            prf,
        })

        expect(params.salt).toEqual(algIdSalt)
        expect(params.iterationCount).toEqual(iterationCount)
        expect(params.keyLength).toEqual(keyLength)
        expect(params.prf.algorithm.value).toEqual(OIDs.HASH.HMAC_SHA256)
    })

    test('constructor should use default prf if not provided', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
        })

        expect(params.prf.algorithm.value).toEqual(OIDs.HASH.HMAC_SHA1)
    })

    test('toAsn1 should return correct ASN.1 structure with all parameters', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
            keyLength,
            prf,
        })

        const asn1 = params.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)
        expect(asn1.children.length).toEqual(3) // salt, iterationCount, keyLength
        expect(asn1.children[0].is(UniversalTag.OctetString)).toBe(true)
        expect(asn1.children[1].is(UniversalTag.Integer)).toBe(true)
        expect(asn1.children[2].is(UniversalTag.Integer)).toBe(true)
    })

    test('toAsn1 should return correct ASN.1 structure without keyLength', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
            prf,
        })

        const asn1 = params.toAsn1()

        expect(asn1.is(UniversalTag.Sequence)).toBe(true)
        expect(asn1.children.length).toEqual(2) // salt, iterationCount
    })

    test('fromAsn1 should parse ASN.1 structure with OctetString salt', () => {
        const saltAsn1 = der.octetString(salt)
        const iterationCountAsn1 = der.integer(iterationCount)
        const keyLengthAsn1 = der.integer(keyLength)
        const prfAsn1 = prf.toAsn1()

        const sequence = der.sequence([
            saltAsn1,
            iterationCountAsn1,
            keyLengthAsn1,
            prfAsn1,
        ])

        const parsed = PBKDF2Params.fromAsn1(sequence)

        expect(parsed).toBeInstanceOf(PBKDF2Params)
        expect(parsed.salt).toBeInstanceOf(OctetString)
        expect(parsed.iterationCount).toEqual(iterationCount)
        expect(parsed.keyLength).toEqual(keyLength)
        expect(parsed.prf.algorithm.value).toEqual(OIDs.HASH.HMAC_SHA256)
    })

    test('fromAsn1 should parse ASN.1 structure with AlgorithmIdentifier salt', () => {
        const algIdSalt = new AlgorithmIdentifier({
            algorithm: OIDs.PKCS5.PBKDF2,
        })

        const saltAsn1 = algIdSalt.toAsn1()
        const iterationCountAsn1 = der.integer(iterationCount)

        const sequence = der.sequence([saltAsn1, iterationCountAsn1])

        const parsed = PBKDF2Params.fromAsn1(sequence)

        expect(parsed).toBeInstanceOf(PBKDF2Params)
        expect(parsed.salt).toBeInstanceOf(AlgorithmIdentifier)
        expect(parsed.iterationCount).toEqual(iterationCount)
    })

    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = der.integer(42)

        expect(() => PBKDF2Params.fromAsn1(notSequence)).toThrow(
            'PBKDF2: expected SEQUENCE',
        )
    })

    test('fromAsn1 should throw if fewer than 2 elements', () => {
        const wrongSequence = der.sequence([der.integer(1)])

        expect(() => PBKDF2Params.fromAsn1(wrongSequence)).toThrow(
            'PBKDF2: expected at least 2 elements',
        )
    })

    test('fromAsn1 should throw if salt has invalid type', () => {
        const wrongSalt = der.boolean(true)
        const iterationCountAsn1 = der.integer(iterationCount)

        const sequence = der.sequence([wrongSalt, iterationCountAsn1])

        expect(() => PBKDF2Params.fromAsn1(sequence)).toThrow(
            'PBKDF2: invalid salt type',
        )
    })

    test('fromAsn1 should throw if iterationCount is not an Integer', () => {
        const saltAsn1 = der.octetString(salt)
        const wrongIterationCount = der.boolean(true)

        const sequence = der.sequence([saltAsn1, wrongIterationCount])

        expect(() => PBKDF2Params.fromAsn1(sequence)).toThrow(
            'PBKDF2: iterationCount must be INTEGER',
        )
    })
})
