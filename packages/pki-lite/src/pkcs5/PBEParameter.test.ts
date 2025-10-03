import { describe, it, expect, assert } from 'vitest'
import { PBEParameter } from './PBEParameter'
import { OctetString } from '../asn1/OctetString.js'
import { asn1js } from '../core/PkiBase.js'

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
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        assert(asn1.valueBlock.value[0] instanceof asn1js.OctetString)
        assert(asn1.valueBlock.value[1] instanceof asn1js.Integer)
        expect(asn1.valueBlock.value[0].valueBlock.valueHexView).toEqual(salt)
        expect(asn1.valueBlock.value[1].valueBlock.valueDec).toEqual(
            iterationCount,
        )
    })

    it('should decode from ASN.1 Sequence', () => {
        const param = new PBEParameter({ salt, iterationCount })
        const asn1 = param.toAsn1()
        const decoded = PBEParameter.fromAsn1(asn1)
        expect(decoded.salt.bytes).toEqual(salt)
        expect(decoded.iterationCount).toEqual(iterationCount)
    })

    it('should throw on invalid ASN.1 structure', () => {
        expect(() =>
            PBEParameter.fromAsn1(new asn1js.Integer({ value: 1 })),
        ).toThrow()
        const badSeq = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })
        expect(() => PBEParameter.fromAsn1(badSeq)).toThrow()
    })
})
