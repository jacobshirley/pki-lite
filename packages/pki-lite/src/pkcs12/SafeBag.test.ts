import { describe, it, expect } from 'vitest'
import { SafeBag } from './SafeBag.js'
import { OctetString } from '../asn1/OctetString.js'
import { SafeContents } from './SafeContents.js'

describe('SafeBag', () => {
    it('encodes and decodes a SafeBag with CertBag value', () => {
        const bagId = '1.2.840.113549.1.9.22.1' // x509Certificate
        const bagValue = new OctetString({
            bytes: new Uint8Array([1, 2, 3, 4]),
        })
        const bag = new SafeBag({ bagId, bagValue })
        const der = bag.toDer()
        const decoded = SafeBag.fromDer(der)
        expect(decoded.bagId.value).toBe(bagId)
        expect(decoded.bagValue.parseAs(OctetString)).toEqual(bagValue)
    })
})

describe('SafeContents', () => {
    it('encodes and decodes a sequence of SafeBag', () => {
        const bag1 = new SafeBag({
            bagId: '1.2.840.113549.1.9.22.1',
            bagValue: new OctetString({ bytes: new Uint8Array([1]) }),
        })
        const bag2 = new SafeBag({
            bagId: '1.2.840.113549.1.9.22.2',
            bagValue: new OctetString({ bytes: new Uint8Array([2]) }),
        })
        const contents = new SafeContents(bag1, bag2)
        const der = contents.toDer()
        const decoded = SafeContents.fromDer(der)
        expect(decoded.length).toBe(2)
        expect(decoded[0].bagId.value).toBe('1.2.840.113549.1.9.22.1')
        expect(decoded[1].bagId.value).toBe('1.2.840.113549.1.9.22.2')
    })
})
