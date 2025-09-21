import { assert, describe, expect, test } from 'vitest'
import { MessageImprint } from './MessageImprint.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'

describe('MessageImprint', () => {
    test('can be created', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const hashedMessage = new Uint8Array([1, 2, 3, 4, 5])

        const messageImprint = new MessageImprint({
            hashAlgorithm,
            hashedMessage,
        })
        expect(messageImprint).toBeInstanceOf(MessageImprint)
        expect(messageImprint.hashAlgorithm).toBe(hashAlgorithm)
        expect(messageImprint.hashedMessage).toEqual(hashedMessage)
    })

    test('can be converted to ASN.1', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const hashedMessage = new Uint8Array([1, 2, 3, 4, 5])

        const messageImprint = new MessageImprint({
            hashAlgorithm,
            hashedMessage,
        })
        const asn1 = messageImprint.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)

        // First element should be AlgorithmIdentifier
        assert(asn1.valueBlock.value[0] instanceof asn1js.Sequence)

        // Second element should be OCTET STRING
        assert(asn1.valueBlock.value[1] instanceof asn1js.OctetString)
        const octetString = asn1.valueBlock.value[1] as asn1js.OctetString
        expect(new Uint8Array(octetString.valueBlock.valueHexView)).toEqual(
            hashedMessage,
        )
    })

    test('can be created from ASN.1', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const hashedMessage = new Uint8Array([1, 2, 3, 4, 5])

        const original = new MessageImprint({ hashAlgorithm, hashedMessage })
        const asn1 = original.toAsn1()
        const recreated = MessageImprint.fromAsn1(asn1)

        expect(recreated.hashAlgorithm.algorithm).toEqual(
            hashAlgorithm.algorithm,
        )
        expect(recreated.hashedMessage).toEqual(hashedMessage)
    })

    test('roundtrip conversion preserves data', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.3',
        }) // SHA-512
        const hashedMessage = crypto.getRandomValues(new Uint8Array(64)) // 512-bit hash

        const original = new MessageImprint({ hashAlgorithm, hashedMessage })
        const asn1 = original.toAsn1()
        const recreated = MessageImprint.fromAsn1(asn1)
        const asn1Again = recreated.toAsn1()

        expect(original.toDer()).toEqual(recreated.toDer())
        expect(asn1.toBER(false)).toEqual(asn1Again.toBER(false))
    })

    test('fromAsn1 throws error for invalid structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 1 })

        expect(() => MessageImprint.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const invalidAsn1 = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })], // Only 1 element instead of 2
        })

        expect(() => MessageImprint.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected exactly 2 elements',
        )
    })

    test('fromAsn1 throws error for invalid hashedMessage type', () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        })
        const invalidAsn1 = new asn1js.Sequence({
            value: [
                hashAlgorithm.toAsn1(),
                new asn1js.Integer({ value: 123 }), // Should be OCTET STRING
            ],
        })

        expect(() => MessageImprint.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected OCTET STRING for hashedMessage',
        )
    })

    test('works with different hash algorithms', () => {
        const testCases = [
            { oid: '1.3.14.3.2.26', name: 'SHA-1' },
            { oid: '2.16.840.1.101.3.4.2.1', name: 'SHA-256' },
            { oid: '2.16.840.1.101.3.4.2.2', name: 'SHA-384' },
            { oid: '2.16.840.1.101.3.4.2.3', name: 'SHA-512' },
        ]

        testCases.forEach(({ oid, name }) => {
            const hashAlgorithm = new AlgorithmIdentifier({ algorithm: oid })
            const hashedMessage = crypto.getRandomValues(new Uint8Array(32))

            const messageImprint = new MessageImprint({
                hashAlgorithm,
                hashedMessage,
            })
            const asn1 = messageImprint.toAsn1()
            const recreated = MessageImprint.fromAsn1(asn1)

            expect(recreated.hashAlgorithm.algorithm.toString()).toBe(oid)
            expect(recreated.hashedMessage).toEqual(hashedMessage)
        })
    })
})
