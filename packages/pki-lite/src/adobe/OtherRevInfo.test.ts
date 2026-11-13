import { OtherRevInfo } from './OtherRevInfo'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { der, UniversalTag } from '../core/PkiBase.js'
import { describe, expect, it } from 'vitest'
import { OctetString } from '../asn1/OctetString'

describe('OtherRevInfo', () => {
    it('should construct with type and value', () => {
        const type = '1.2.3.4.5'
        const valueBytes = new Uint8Array([1, 2, 3, 4])
        const otherRevInfo = new OtherRevInfo({ type, value: valueBytes })
        expect(otherRevInfo.type.value).toEqual(type)
        expect(otherRevInfo.value.derBytes).toEqual(valueBytes)
    })

    it('should encode to ASN.1 sequence', () => {
        const type = '1.2.3.4.5'
        const valueBytes = new OctetString({
            bytes: new Uint8Array([1, 2, 3, 4]),
        })
        const otherRevInfo = new OtherRevInfo({ type, value: valueBytes })
        const asn1 = otherRevInfo.toAsn1()
        expect(asn1.is(UniversalTag.Sequence)).toBe(true)
        expect(asn1.children.length).toEqual(2)
        expect(der.readOid(asn1.children[0])).toEqual(type)
        // The value should be an octet string
        expect(asn1.children[1].is(UniversalTag.OctetString)).toBe(true)
        expect(new Uint8Array(asn1.children[1].bytes())).toEqual(
            valueBytes.bytes,
        )
    })

    it('should decode from ASN.1 sequence', () => {
        const type = '1.2.3.4.5.6'
        const valueBytes = new Uint8Array([99, 88, 77])
        const oid = new ObjectIdentifier({ value: type }).toAsn1()
        const octetString = new OctetString({ bytes: valueBytes })
        const seq = der.sequence([oid, octetString.toAsn1()])
        const decoded = OtherRevInfo.fromAsn1(seq)
        expect(decoded.type.value).toEqual(type)
        expect(decoded.value.parseAs(OctetString).bytes).toEqual(valueBytes)
    })

    it('should throw if ASN.1 sequence is malformed', () => {
        const seq = der.sequence([])
        expect(() => OtherRevInfo.fromAsn1(seq)).toThrow()
    })
})
