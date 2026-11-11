import { describe, expect, it } from 'vitest'
import { CRLReason } from './CRLReason.js'
import { der, derToAsn1 } from '../core/PkiBase.js'

describe('CRLReason', () => {
    it('should skip value 7 as per RFC', () => {
        const values = Object.values(CRLReason)
        expect(values).not.toContain(7)
    })

    it('should have all expected reason codes', () => {
        const expectedReasons = [
            'unspecified',
            'keyCompromise',
            'cACompromise',
            'affiliationChanged',
            'superseded',
            'cessationOfOperation',
            'certificateHold',
            'removeFromCRL',
            'privilegeWithdrawn',
            'aACompromise',
        ]
        const actualReasons = Object.keys(CRLReason)

        expect(actualReasons.sort()).toEqual(expectedReasons.sort())
    })

    it('round-trips through DER as an ENUMERATED', () => {
        const encoded = CRLReason.keyCompromise.toDer()
        expect(encoded).toEqual(new Uint8Array([0x0a, 0x01, 0x01]))
        expect(CRLReason.fromAsn1(derToAsn1(encoded)).toDer()).toEqual(encoded)
    })

    it('rejects an INTEGER', () => {
        expect(() => CRLReason.fromAsn1(der.integer(1))).toThrow(
            'Expected ENUMERATED',
        )
    })
})
