import { describe, it, expect } from 'vitest'
import { OtherRecipientInfo } from './OtherRecipientInfo.js'
import { OctetString } from '../../asn1/OctetString.js'
import { OIDs } from '../../core/OIDs.js'

describe('OtherRecipientInfo', () => {
    it('should convert to and from ASN.1', () => {
        const oriType = OIDs.RSA.ENCRYPTION
        const oriValue = new OctetString({
            bytes: new Uint8Array([1, 2, 3, 4]),
        })
        const original = new OtherRecipientInfo({
            oriType: oriType,
            oriValue: oriValue.toAsn1(),
        })

        const asn1 = original.toAsn1()
        const restored = OtherRecipientInfo.fromAsn1(asn1)

        expect(restored).toBeInstanceOf(OtherRecipientInfo)
        expect(restored.oriType).toEqual(original.oriType)
        expect(restored.oriValue.isEqual(original.oriValue)).toBe(true)
    })
})
