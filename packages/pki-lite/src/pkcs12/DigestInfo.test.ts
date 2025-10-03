import { describe, it, expect } from 'vitest'
import { DigestInfo } from './DigestInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'

describe('DigestInfo', () => {
    it('encodes and decodes correctly', () => {
        const alg = new AlgorithmIdentifier({
            algorithm: '1.3.14.3.2.26', // SHA-1
        })
        const digest = new OctetString({ bytes: new Uint8Array([1, 2, 3, 4]) })
        const di = new DigestInfo({ digestAlgorithm: alg, digest })
        const der = di.toDer()
        const decoded = DigestInfo.fromDer(der)
        expect(decoded.digestAlgorithm.algorithm.value).toEqual('1.3.14.3.2.26')
        expect(Array.from(decoded.digest.bytes)).toEqual([1, 2, 3, 4])
    })
})
