import { describe, it, expect } from 'vitest'
import { MacData } from './MacData.js'
import { DigestInfo } from './DigestInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'

describe('MacData', () => {
    it('encodes and decodes with default iterations', () => {
        const mac = new DigestInfo({
            digestAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.3.14.3.2.26',
            }),
            digest: new OctetString({ bytes: new Uint8Array([1, 2, 3]) }),
        })
        const macSalt = new OctetString({ bytes: new Uint8Array([4, 5, 6]) })
        const md = new MacData({ mac, macSalt })
        const der = md.toDer()
        const decoded = MacData.fromDer(der)
        expect(decoded.iterations).toEqual(1)
        expect(Array.from(decoded.macSalt.bytes)).toEqual([4, 5, 6])
    })

    it('encodes and decodes with explicit iterations', () => {
        const mac = new DigestInfo({
            digestAlgorithm: new AlgorithmIdentifier({
                algorithm: '1.3.14.3.2.26',
            }),
            digest: new OctetString({ bytes: new Uint8Array([1, 2, 3]) }),
        })
        const macSalt = new OctetString({ bytes: new Uint8Array([4, 5, 6]) })
        const md = new MacData({ mac, macSalt, iterations: 2048 })
        const der = md.toDer()
        const decoded = MacData.fromDer(der)
        expect(decoded.iterations).toEqual(2048)
    })
})
