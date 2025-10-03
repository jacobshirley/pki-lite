import { describe, expect, it } from 'vitest'
import { RSASSAPSSParams } from './RSASSAPSSParams.js'
import { AlgorithmIdentifier } from './AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'

describe('RSASSAPSSParams', () => {
    it('should create with default constructor', () => {
        const params = new RSASSAPSSParams({})
        expect(params.hashAlgorithm).toBeUndefined()
        expect(params.maskGenAlgorithm).toBeUndefined()
        expect(params.saltLength).toBeUndefined()
        expect(params.trailerField).toBeUndefined()
    })

    it('should create with all parameters specified', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg,
        }) // MGF1 with SHA-256
        const saltLength = 32
        const trailerField = 1

        const params = new RSASSAPSSParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            saltLength: saltLength,
            trailerField: trailerField,
        })
        expect(params.hashAlgorithm).toEqual(hashAlg)
        expect(params.maskGenAlgorithm).toEqual(mgfAlg)
        expect(params.saltLength).toEqual(saltLength)
        expect(params.trailerField).toEqual(trailerField)
    })

    it('should convert to ASN.1 with all parameters', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg,
        }) // MGF1 with SHA-256
        const saltLength = 32
        const trailerField = 1

        const params = new RSASSAPSSParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            saltLength: saltLength,
            trailerField: trailerField,
        })
        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // Check that all four parameters are present
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value.length).toEqual(4)

        // Each parameter should be a context-specific tagged value
        expect((sequence.valueBlock.value[0] as any).idBlock.tagClass).toEqual(
            3,
        ) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[0] as any).idBlock.tagNumber).toEqual(
            0,
        ) // hashAlgorithm [0]

        expect((sequence.valueBlock.value[1] as any).idBlock.tagClass).toEqual(
            3,
        ) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[1] as any).idBlock.tagNumber).toEqual(
            1,
        ) // maskGenAlgorithm [1]

        expect((sequence.valueBlock.value[2] as any).idBlock.tagClass).toEqual(
            3,
        ) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[2] as any).idBlock.tagNumber).toEqual(
            2,
        ) // saltLength [2]

        expect((sequence.valueBlock.value[3] as any).idBlock.tagClass).toEqual(
            3,
        ) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[3] as any).idBlock.tagNumber).toEqual(
            3,
        ) // trailerField [3]
    })

    it('should convert to ASN.1 with no parameters (empty sequence)', () => {
        const params = new RSASSAPSSParams({})
        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // No parameters should result in an empty sequence
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value.length).toEqual(0)
    })

    it('should convert to ASN.1 with partial parameters', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const saltLength = 32

        const params = new RSASSAPSSParams({
            hashAlgorithm: hashAlg,
            saltLength: saltLength,
        })
        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // Only hashAlgorithm and saltLength should be present
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value.length).toEqual(2)

        // Verify parameters are correctly tagged
        expect((sequence.valueBlock.value[0] as any).idBlock.tagNumber).toEqual(
            0,
        ) // hashAlgorithm [0]
        expect((sequence.valueBlock.value[1] as any).idBlock.tagNumber).toEqual(
            2,
        ) // saltLength [2]
    })

    it('should parse from ASN.1 with all parameters', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg,
        }) // MGF1 with SHA-256
        const saltLength = 32
        const trailerField = 1

        const original = new RSASSAPSSParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            saltLength: saltLength,
            trailerField: trailerField,
        })
        const asn1 = original.toAsn1()
        const parsed = RSASSAPSSParams.fromAsn1(asn1)

        expect(parsed.hashAlgorithm).toBeDefined()
        expect(parsed.hashAlgorithm?.algorithm.toString()).toEqual(
            '2.16.840.1.101.3.4.2.1',
        )

        expect(parsed.maskGenAlgorithm).toBeDefined()
        expect(parsed.maskGenAlgorithm?.algorithm.toString()).toEqual(
            '1.2.840.113549.1.1.8',
        )

        expect(parsed.saltLength).toEqual(saltLength)
        expect(parsed.trailerField).toEqual(trailerField)
    })

    it('should parse from ASN.1 with partial parameters', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const saltLength = 32

        const original = new RSASSAPSSParams({
            hashAlgorithm: hashAlg,
            saltLength: saltLength,
        })
        const asn1 = original.toAsn1()
        const parsed = RSASSAPSSParams.fromAsn1(asn1)

        expect(parsed.hashAlgorithm).toBeDefined()
        expect(parsed.hashAlgorithm?.algorithm.toString()).toEqual(
            '2.16.840.1.101.3.4.2.1',
        )

        expect(parsed.maskGenAlgorithm).toBeUndefined()
        expect(parsed.saltLength).toEqual(saltLength)
        expect(parsed.trailerField).toBeUndefined()
    })

    it('should round-trip to and from DER encoding', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg,
        }) // MGF1 with SHA-256
        const saltLength = 32
        const trailerField = 1

        const original = new RSASSAPSSParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            saltLength: saltLength,
            trailerField: trailerField,
        })
        const der = original.toDer()

        // Parse the DER encoding back
        const arrayBuffer = der.buffer.slice(
            der.byteOffset,
            der.byteOffset + der.byteLength,
        )
        const asn1 = asn1js.fromBER(arrayBuffer as ArrayBuffer).result
        const parsed = RSASSAPSSParams.fromAsn1(asn1)

        expect(parsed.hashAlgorithm).toBeDefined()
        expect(parsed.hashAlgorithm?.algorithm.toString()).toEqual(
            '2.16.840.1.101.3.4.2.1',
        )

        expect(parsed.maskGenAlgorithm).toBeDefined()
        expect(parsed.maskGenAlgorithm?.algorithm.toString()).toEqual(
            '1.2.840.113549.1.1.8',
        )

        expect(parsed.saltLength).toEqual(saltLength)
        expect(parsed.trailerField).toEqual(trailerField)
    })

    it('should get effective parameters with defaults', () => {
        const params = new RSASSAPSSParams({})

        const hashAlg = params.getEffectiveHashAlgorithm()
        expect(hashAlg).toBeDefined()
        expect(hashAlg.algorithm.toString()).toEqual('1.3.14.3.2.26') // SHA-1

        const mgfAlg = params.getEffectiveMaskGenAlgorithm()
        expect(mgfAlg).toBeDefined()
        expect(mgfAlg.algorithm.toString()).toEqual('1.2.840.113549.1.1.8') // MGF1

        const saltLength = params.getEffectiveSaltLength()
        expect(saltLength).toEqual(20) // Default salt length for SHA-1

        const trailerField = params.getEffectiveTrailerField()
        expect(trailerField).toEqual(1) // trailerFieldBC
    })

    it('should create default instance', () => {
        const params = RSASSAPSSParams.createDefault()
        expect(params).toBeInstanceOf(RSASSAPSSParams)
        expect(params.hashAlgorithm).toBeUndefined()
        expect(params.maskGenAlgorithm).toBeUndefined()
        expect(params.saltLength).toBeUndefined()
        expect(params.trailerField).toBeUndefined()
    })
})
