import { describe, expect, it } from 'vitest'
import { RSAESOAEPParams } from './RSAESOAEPParams.js'
import { AlgorithmIdentifier, PSourceAlgorithm } from './AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'

describe('RSAESOAEPParams', () => {
    it('should create with default constructor', () => {
        const params = new RSAESOAEPParams()
        expect(params.hashAlgorithm).toBeUndefined()
        expect(params.maskGenAlgorithm).toBeUndefined()
        expect(params.pSourceAlgorithm).toBeUndefined()
    })

    it('should create with all parameters specified', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg.toDer(),
        }) // MGF1 with SHA-256
        const pSourceAlg = new PSourceAlgorithm()

        const params = new RSAESOAEPParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            pSourceAlgorithm: pSourceAlg,
        })
        expect(params.hashAlgorithm).toBe(hashAlg)
        expect(params.maskGenAlgorithm).toBe(mgfAlg)
        expect(params.pSourceAlgorithm).toEqual(pSourceAlg)
    })

    it('should convert to ASN.1 with all parameters', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg.toDer(),
        }) // MGF1 with SHA-256
        const pSourceAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.9',
            // pSpecified
            parameters: new OctetString({
                bytes: new Uint8Array([1, 2, 3, 4]),
            }).toDer(),
        })

        const params = new RSAESOAEPParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            pSourceAlgorithm: pSourceAlg,
        })
        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // Check that all three parameters are present
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value.length).toBe(3)

        // Each parameter should be a context-specific tagged value
        expect((sequence.valueBlock.value[0] as any).idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[0] as any).idBlock.tagNumber).toBe(0) // hashAlgorithm [0]

        expect((sequence.valueBlock.value[1] as any).idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[1] as any).idBlock.tagNumber).toBe(1) // maskGenAlgorithm [1]

        expect((sequence.valueBlock.value[2] as any).idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect((sequence.valueBlock.value[2] as any).idBlock.tagNumber).toBe(2) // pSourceAlgorithm [2]
    })

    it('should convert to ASN.1 with no parameters (empty sequence)', () => {
        const params = new RSAESOAEPParams()
        const asn1 = params.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)

        // No parameters should result in an empty sequence
        const sequence = asn1 as asn1js.Sequence
        expect(sequence.valueBlock.value.length).toBe(0)
    })

    it('should parse from ASN.1 with all parameters', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg.toDer(),
        }) // MGF1 with SHA-256
        const pSourceAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.9',
            // pSpecified
            parameters: new OctetString({
                bytes: new Uint8Array([1, 2, 3, 4]),
            }).toDer(),
        })

        const original = new RSAESOAEPParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            pSourceAlgorithm: pSourceAlg,
        })
        const asn1 = original.toAsn1()
        const parsed = RSAESOAEPParams.fromAsn1(asn1)

        expect(parsed.hashAlgorithm).toBeDefined()
        expect(parsed.hashAlgorithm?.algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.1',
        )

        expect(parsed.maskGenAlgorithm).toBeDefined()
        expect(parsed.maskGenAlgorithm?.algorithm.toString()).toBe(
            '1.2.840.113549.1.1.8',
        )

        expect(parsed.pSourceAlgorithm).toBeDefined()
        expect(parsed.pSourceAlgorithm?.algorithm.toString()).toBe(
            '1.2.840.113549.1.1.9',
        )
    })

    it('should round-trip to and from DER encoding', () => {
        const hashAlg = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1',
        }) // SHA-256
        const mgfAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.8',
            parameters: hashAlg.toDer(),
        }) // MGF1 with SHA-256
        const pSourceAlg = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.9',
            // pSpecified
            parameters: new OctetString({
                bytes: new Uint8Array([1, 2, 3, 4]),
            }).toDer(),
        })

        const original = new RSAESOAEPParams({
            hashAlgorithm: hashAlg,
            maskGenAlgorithm: mgfAlg,
            pSourceAlgorithm: pSourceAlg,
        })
        const der = original.toDer()

        // Parse the DER encoding back
        // Create a new ArrayBuffer from the Uint8Array to ensure we have a proper BufferSource
        const arrayBuffer = der.buffer.slice(
            der.byteOffset,
            der.byteOffset + der.byteLength,
        )
        const asn1 = asn1js.fromBER(arrayBuffer as ArrayBuffer).result
        const parsed = RSAESOAEPParams.fromAsn1(asn1)

        expect(parsed.hashAlgorithm).toBeDefined()
        expect(parsed.hashAlgorithm?.algorithm.toString()).toBe(
            '2.16.840.1.101.3.4.2.1',
        )

        expect(parsed.maskGenAlgorithm).toBeDefined()
        expect(parsed.maskGenAlgorithm?.algorithm.toString()).toBe(
            '1.2.840.113549.1.1.8',
        )

        expect(parsed.pSourceAlgorithm).toBeDefined()
        expect(parsed.pSourceAlgorithm?.algorithm.toString()).toBe(
            '1.2.840.113549.1.1.9',
        )
    })

    it('should get effective parameters with defaults', () => {
        const params = new RSAESOAEPParams()

        const hashAlg = params.getEffectiveHashAlgorithm()
        expect(hashAlg).toBeDefined()
        expect(hashAlg.algorithm.toString()).toBe('1.3.14.3.2.26') // SHA-1

        const mgfAlg = params.getEffectiveMaskGenAlgorithm()
        expect(mgfAlg).toBeDefined()
        expect(mgfAlg.algorithm.toString()).toBe('1.2.840.113549.1.1.8') // MGF1

        const pSourceAlg = params.getEffectivePSourceAlgorithm()
        expect(pSourceAlg).toBeDefined()
        expect(pSourceAlg.algorithm.toString()).toBe('1.2.840.113549.1.1.9') // pSpecified
    })

    it('should create default instance', () => {
        const params = RSAESOAEPParams.createDefault()
        expect(params).toBeInstanceOf(RSAESOAEPParams)
        expect(params.hashAlgorithm).toBeUndefined()
        expect(params.maskGenAlgorithm).toBeUndefined()
        expect(params.pSourceAlgorithm).toBeUndefined()
    })
})
