import { describe, test, expect } from 'vitest'
import { PBES2Params } from './PBES2Params.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../core/OIDs.js'
import { asn1js } from '../core/PkiBase.js'

describe('PBES2Params', () => {
    const keyDerivationFunc = new AlgorithmIdentifier({
        algorithm: OIDs.PKCS5.PBKDF2,
    })

    const encryptionScheme = new AlgorithmIdentifier({
        algorithm: OIDs.ENCRYPTION.AES_256_CBC,
    })

    test('constructor should set properties correctly', () => {
        const pbes2Params = new PBES2Params({
            keyDerivationFunc,
            encryptionScheme,
        })

        expect(pbes2Params.keyDerivationFunc).toBe(keyDerivationFunc)
        expect(pbes2Params.encryptionScheme).toBe(encryptionScheme)
    })

    test('toAsn1 should return correct ASN.1 structure', () => {
        const pbes2Params = new PBES2Params({
            keyDerivationFunc,
            encryptionScheme,
        })

        const asn1 = pbes2Params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)
        // Just check that the results look like algorithm identifiers
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)
    })

    test('fromAsn1 should parse ASN.1 structure correctly', () => {
        const original = new PBES2Params({
            keyDerivationFunc,
            encryptionScheme,
        })

        const asn1 = original.toAsn1()
        const parsed = PBES2Params.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(PBES2Params)
        expect(parsed.keyDerivationFunc.algorithm.value).toBe(OIDs.PKCS5.PBKDF2)
        expect(parsed.encryptionScheme.algorithm.value).toBe(
            OIDs.ENCRYPTION.AES_256_CBC,
        )
    })

    test('fromDer should parse DER-encoded data correctly', () => {
        const original = new PBES2Params({
            keyDerivationFunc,
            encryptionScheme,
        })

        const asn1 = original.toAsn1()
        const der = asn1.toBER(false)
        const parsed = PBES2Params.fromDer(new Uint8Array(der))

        expect(parsed).toBeInstanceOf(PBES2Params)
        expect(parsed.keyDerivationFunc.algorithm.value).toBe(OIDs.PKCS5.PBKDF2)
        expect(parsed.encryptionScheme.algorithm.value).toBe(
            OIDs.ENCRYPTION.AES_256_CBC,
        )
    })

    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = new asn1js.Integer({ value: 42 })

        expect(() => PBES2Params.fromAsn1(notSequence)).toThrow(
            'PBES2Params: expected SEQUENCE',
        )
    })

    test('fromAsn1 should throw if not exactly 2 elements', () => {
        const wrongSequence = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })

        expect(() => PBES2Params.fromAsn1(wrongSequence)).toThrow(
            'PBES2Params: expected 2 elements',
        )
    })
})
