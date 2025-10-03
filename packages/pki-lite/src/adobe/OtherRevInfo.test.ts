import { OtherRevInfo } from './OtherRevInfo'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
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
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)
        expect(
            (
                asn1.valueBlock.value[0] as asn1js.ObjectIdentifier
            ).valueBlock.toString(),
        ).toEqual(type)
        // The value should be an octet string
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.OctetString)
        expect(
            new Uint8Array(
                (
                    asn1.valueBlock.value[1] as asn1js.OctetString
                ).valueBlock.valueHexView,
            ),
        ).toEqual(valueBytes.bytes)
    })

    it('should decode from ASN.1 sequence', () => {
        const type = '1.2.3.4.5.6'
        const valueBytes = new Uint8Array([99, 88, 77])
        const oid = new ObjectIdentifier({ value: type }).toAsn1()
        const octetString = new OctetString({ bytes: valueBytes })
        const seq = new asn1js.Sequence({ value: [oid, octetString.toAsn1()] })
        const decoded = OtherRevInfo.fromAsn1(seq)
        expect(decoded.type.value).toEqual(type)
        expect(decoded.value.parseAs(OctetString).bytes).toEqual(valueBytes)
    })

    it('should throw if ASN.1 sequence is malformed', () => {
        const seq = new asn1js.Sequence({ value: [] })
        expect(() => OtherRevInfo.fromAsn1(seq)).toThrow()
    })
})
