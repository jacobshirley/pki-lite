import { describe, expect, test } from 'vitest'
import { BasicConstraints } from './BasicConstraints.js'
import * as asn1js from 'asn1js'

describe('BasicConstraints', () => {
    test('should create BasicConstraints with cA true and no pathLenConstraint', () => {
        const basicConstraints = new BasicConstraints({
            cA: true,
        })

        expect(basicConstraints.cA).toBe(true)
        expect(basicConstraints.pathLenConstraint).toBeUndefined()
    })

    test('should create BasicConstraints with cA false and no pathLenConstraint', () => {
        const basicConstraints = new BasicConstraints({
            cA: false,
        })

        expect(basicConstraints.cA).toBe(false)
        expect(basicConstraints.pathLenConstraint).toBeUndefined()
    })

    test('should create BasicConstraints with cA true and pathLenConstraint', () => {
        const basicConstraints = new BasicConstraints({
            cA: true,
            pathLenConstraint: 3,
        })

        expect(basicConstraints.cA).toBe(true)
        expect(basicConstraints.pathLenConstraint).toBe(3)
    })

    test('should create BasicConstraints with cA false and pathLenConstraint 0', () => {
        const basicConstraints = new BasicConstraints({
            cA: false,
            pathLenConstraint: 0,
        })

        expect(basicConstraints.cA).toBe(false)
        expect(basicConstraints.pathLenConstraint).toBe(0)
    })

    test('should convert to ASN.1 structure with only cA', () => {
        const basicConstraints = new BasicConstraints({
            cA: true,
        })

        const asn1 = basicConstraints.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(1)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Boolean)
        expect(
            (asn1.valueBlock.value[0] as asn1js.Boolean).valueBlock.value,
        ).toBe(true)
    })

    test('should convert to ASN.1 structure with cA and pathLenConstraint', () => {
        const basicConstraints = new BasicConstraints({
            cA: true,
            pathLenConstraint: 5,
        })

        const asn1 = basicConstraints.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Boolean)
        expect(
            (asn1.valueBlock.value[0] as asn1js.Boolean).valueBlock.value,
        ).toBe(true)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Integer)
        expect(
            (asn1.valueBlock.value[1] as asn1js.Integer).valueBlock.valueDec,
        ).toBe(5)
    })

    test('should parse from ASN.1 structure with only cA', () => {
        const asn1 = new asn1js.Sequence({
            value: [new asn1js.Boolean({ value: false })],
        })

        const basicConstraints = BasicConstraints.fromAsn1(asn1)
        expect(basicConstraints.cA).toBe(false)
        expect(basicConstraints.pathLenConstraint).toBeUndefined()
    })

    test('should parse from ASN.1 structure with cA and pathLenConstraint', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Boolean({ value: true }),
                new asn1js.Integer({ value: 2 }),
            ],
        })

        const basicConstraints = BasicConstraints.fromAsn1(asn1)
        expect(basicConstraints.cA).toBe(true)
        expect(basicConstraints.pathLenConstraint).toBe(2)
    })

    test('fromAsn1 should throw error for empty sequence', () => {
        const asn1 = new asn1js.Sequence({ value: [] })

        expect(() => BasicConstraints.fromAsn1(asn1)).toThrow(
            'Invalid BasicConstraints ASN.1 structure',
        )
    })

    test('fromAsn1 should throw error for invalid cA type', () => {
        const asn1 = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })], // Should be Boolean
        })

        expect(() => BasicConstraints.fromAsn1(asn1)).toThrow(
            'Invalid BasicConstraints ASN.1 structure: cA is not a Boolean',
        )
    })

    test('fromAsn1 should throw error for invalid pathLenConstraint type', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Boolean({ value: true }),
                new asn1js.Boolean({ value: false }), // Should be Integer
            ],
        })

        expect(() => BasicConstraints.fromAsn1(asn1)).toThrow(
            'Invalid BasicConstraints ASN.1 structure: pathLenConstraint is not an Integer',
        )
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testCases = [
            { cA: true },
            { cA: false },
            { cA: true, pathLenConstraint: 0 },
            { cA: true, pathLenConstraint: 5 },
            { cA: false, pathLenConstraint: 10 },
        ]

        for (const testCase of testCases) {
            const original = new BasicConstraints(testCase)
            const asn1 = original.toAsn1()
            const decoded = BasicConstraints.fromAsn1(asn1)

            expect(decoded.cA).toBe(testCase.cA)
            expect(decoded.pathLenConstraint).toBe(testCase.pathLenConstraint)
        }
    })

    test('should handle CA certificates with path length constraints', () => {
        // Root CA - no path length constraint
        const rootCA = new BasicConstraints({ cA: true })
        expect(rootCA.cA).toBe(true)
        expect(rootCA.pathLenConstraint).toBeUndefined()

        // Intermediate CA with path length constraint of 0 (can only issue end-entity certs)
        const intermediateCA = new BasicConstraints({
            cA: true,
            pathLenConstraint: 0,
        })
        expect(intermediateCA.cA).toBe(true)
        expect(intermediateCA.pathLenConstraint).toBe(0)

        // End-entity certificate
        const endEntity = new BasicConstraints({ cA: false })
        expect(endEntity.cA).toBe(false)
        expect(endEntity.pathLenConstraint).toBeUndefined()
    })

    test('should handle large path length constraints', () => {
        const basicConstraints = new BasicConstraints({
            cA: true,
            pathLenConstraint: 255,
        })

        expect(basicConstraints.pathLenConstraint).toBe(255)

        // Test round-trip
        const asn1 = basicConstraints.toAsn1()
        const decoded = BasicConstraints.fromAsn1(asn1)
        expect(decoded.pathLenConstraint).toBe(255)
    })
})
