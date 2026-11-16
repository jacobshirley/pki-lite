import { describe, it, expect, assert } from 'vitest'
import { PBEParameter } from './PBEParameter'
import { OctetString } from '../asn1/OctetString.js'
import { der, UniversalTag } from '../core/PkiBase.js'

const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
const iterationCount = 2048

describe('PBEParameter', () => {
    it('should construct with salt and iterationCount', () => {
        const param = new PBEParameter({ salt, iterationCount })
        expect(param.salt).toBeInstanceOf(OctetString)
        expect(param.salt.bytes).toEqual(salt)
        expect(param.iterationCount).toEqual(iterationCount)
    })

    it('should encode to ASN.1 Sequence', () => {
        const param = new PBEParameter({ salt, iterationCount })
        const asn1 = param.toAsn1()
        expect(asn1.is(UniversalTag.Sequence)).toBe(true)
        assert(asn1.children[0]?.is(UniversalTag.OctetString))
        assert(asn1.children[1]?.is(UniversalTag.Integer))
        expect(asn1.children[0].bytes()).toEqual(salt)
        expect(der.readNumber(asn1.children[1])).toEqual(iterationCount)
    })

    it('should decode from ASN.1 Sequence', () => {
        const param = new PBEParameter({ salt, iterationCount })
        const asn1 = param.toAsn1()
        const decoded = PBEParameter.fromAsn1(asn1)
        expect(decoded.salt.bytes).toEqual(salt)
        expect(decoded.iterationCount).toEqual(iterationCount)
    })

    it('should throw on invalid ASN.1 structure', () => {
        expect(() => PBEParameter.fromAsn1(der.integer(1))).toThrow()
        const badSeq = der.sequence([der.integer(1)])
        expect(() => PBEParameter.fromAsn1(badSeq)).toThrow()
    })
})
