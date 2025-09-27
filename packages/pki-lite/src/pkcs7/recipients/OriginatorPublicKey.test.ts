import { describe, it, expect } from 'vitest'
import { OriginatorPublicKey } from './OriginatorPublicKey.js'
import { OIDs } from '../../core/OIDs.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'

describe('OriginatorPublicKey', () => {
    it('should convert to and from ASN.1', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: OIDs.RSA.ENCRYPTION,
        })
        const publicKey = new Uint8Array([1, 2, 3, 4])
        const original = new OriginatorPublicKey({ algorithm, publicKey })

        const asn1 = original.toAsn1()
        const restored = OriginatorPublicKey.fromAsn1(asn1)

        expect(restored).toBeInstanceOf(OriginatorPublicKey)
        expect(restored.algorithm).toEqual(original.algorithm)
        expect(restored.publicKey).toEqual(original.publicKey)
    })
})
