import { describe, test, expect } from 'vitest'
import { PBKDF2Params } from './PBKDF2Params.js'
import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { asn1js } from '../core/PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'

describe('PBKDF2Params', () => {
    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const iterationCount = 2000
    const keyLength = 32
    const prf = new DigestAlgorithmIdentifier({
        algorithm: OIDs.HASH.HMAC_SHA256,
    })

    test('constructor should set properties with Uint8Array salt', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
            keyLength,
            prf,
        })

        expect(params.salt).toBeInstanceOf(OctetString)
        expect(params.iterationCount).toBe(iterationCount)
        expect(params.keyLength).toBe(keyLength)
        expect(params.prf.algorithm.value).toBe(OIDs.HASH.HMAC_SHA256)
    })

    test('constructor should set properties with OctetString salt', () => {
        const octetStringSalt = new OctetString({ bytes: salt })
        const params = new PBKDF2Params({
            salt: octetStringSalt,
            iterationCount,
            keyLength,
            prf,
        })

        expect(params.salt).toBe(octetStringSalt)
        expect(params.iterationCount).toBe(iterationCount)
        expect(params.keyLength).toBe(keyLength)
        expect(params.prf.algorithm.value).toBe(OIDs.HASH.HMAC_SHA256)
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

        expect(params.salt).toBe(algIdSalt)
        expect(params.iterationCount).toBe(iterationCount)
        expect(params.keyLength).toBe(keyLength)
        expect(params.prf.algorithm.value).toBe(OIDs.HASH.HMAC_SHA256)
    })

    test('constructor should use default prf if not provided', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
        })

        expect(params.prf.algorithm.value).toBe(OIDs.HASH.HMAC_SHA1)
    })

    test('toAsn1 should return correct ASN.1 structure with all parameters', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
            keyLength,
            prf,
        })

        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3) // salt, iterationCount, keyLength
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.OctetString)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Integer)
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.Integer)
    })

    test('toAsn1 should return correct ASN.1 structure without keyLength', () => {
        const params = new PBKDF2Params({
            salt,
            iterationCount,
            prf,
        })

        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2) // salt, iterationCount
    })

    test('fromAsn1 should parse ASN.1 structure with OctetString salt', () => {
        const saltAsn1 = new asn1js.OctetString({ valueHex: salt })
        const iterationCountAsn1 = new asn1js.Integer({ value: iterationCount })
        const keyLengthAsn1 = new asn1js.Integer({ value: keyLength })
        const prfAsn1 = prf.toAsn1()

        const sequence = new asn1js.Sequence({
            value: [saltAsn1, iterationCountAsn1, keyLengthAsn1, prfAsn1],
        })

        const parsed = PBKDF2Params.fromAsn1(sequence)

        expect(parsed).toBeInstanceOf(PBKDF2Params)
        expect(parsed.salt).toBeInstanceOf(OctetString)
        expect(parsed.iterationCount).toBe(iterationCount)
        expect(parsed.keyLength).toBe(keyLength)
        expect(parsed.prf.algorithm.value).toBe(OIDs.HASH.HMAC_SHA256)
    })

    test('fromAsn1 should parse ASN.1 structure with AlgorithmIdentifier salt', () => {
        const algIdSalt = new AlgorithmIdentifier({
            algorithm: OIDs.PKCS5.PBKDF2,
        })

        const saltAsn1 = algIdSalt.toAsn1()
        const iterationCountAsn1 = new asn1js.Integer({ value: iterationCount })

        const sequence = new asn1js.Sequence({
            value: [saltAsn1, iterationCountAsn1],
        })

        const parsed = PBKDF2Params.fromAsn1(sequence)

        expect(parsed).toBeInstanceOf(PBKDF2Params)
        expect(parsed.salt).toBeInstanceOf(AlgorithmIdentifier)
        expect(parsed.iterationCount).toBe(iterationCount)
    })

    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = new asn1js.Integer({ value: 42 })

        expect(() => PBKDF2Params.fromAsn1(notSequence)).toThrow(
            'PBKDF2: expected SEQUENCE',
        )
    })

    test('fromAsn1 should throw if fewer than 2 elements', () => {
        const wrongSequence = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })

        expect(() => PBKDF2Params.fromAsn1(wrongSequence)).toThrow(
            'PBKDF2: expected at least 2 elements',
        )
    })

    test('fromAsn1 should throw if salt has invalid type', () => {
        const wrongSalt = new asn1js.Boolean({ value: true })
        const iterationCountAsn1 = new asn1js.Integer({ value: iterationCount })

        const sequence = new asn1js.Sequence({
            value: [wrongSalt, iterationCountAsn1],
        })

        expect(() => PBKDF2Params.fromAsn1(sequence)).toThrow(
            'PBKDF2: invalid salt type',
        )
    })

    test('fromAsn1 should throw if iterationCount is not an Integer', () => {
        const saltAsn1 = new asn1js.OctetString({ valueHex: salt })
        const wrongIterationCount = new asn1js.Boolean({ value: true })

        const sequence = new asn1js.Sequence({
            value: [saltAsn1, wrongIterationCount],
        })

        expect(() => PBKDF2Params.fromAsn1(sequence)).toThrow(
            'PBKDF2: iterationCount must be INTEGER',
        )
    })
})
