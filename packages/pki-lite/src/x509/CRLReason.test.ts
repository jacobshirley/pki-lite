import { describe, expect, it } from 'vitest'
import { CRLReason } from './CRLReason.js'

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
})
