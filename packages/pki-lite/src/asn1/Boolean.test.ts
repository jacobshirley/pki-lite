import { describe, it, expect } from 'vitest'
import { Boolean } from './Boolean.js'
import { asn1js } from '../core/PkiBase.js'

describe('Boolean', () => {
    it('should encode and decode true', () => {
        const bool = new Boolean({ value: true })
        const asn1 = bool.toAsn1()
        const decoded = Boolean.fromAsn1(asn1)
        expect(decoded.value).toEqual(true)
    })

    it('should encode and decode false', () => {
        const bool = new Boolean({ value: false })
        const asn1 = bool.toAsn1()
        const decoded = Boolean.fromAsn1(asn1)
        expect(decoded.value).toEqual(false)
    })

    it('should throw if ASN.1 is not a Boolean', () => {
        expect(() => Boolean.fromAsn1(new asn1js.Null())).toThrow(
            'Invalid ASN.1 structure: expected Boolean but got Null',
        )
    })

    it('should throw if value is not boolean', () => {
        // @ts-expect-error
        expect(() => new Boolean({ value: 1 })).toThrow(
            'Boolean value must be a boolean',
        )
    })

    it('toString should return string value', () => {
        expect(new Boolean({ value: true }).toString()).toEqual('true')
        expect(new Boolean({ value: false }).toString()).toEqual('false')
    })
})
