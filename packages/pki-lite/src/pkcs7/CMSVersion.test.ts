import { describe, it, expect } from 'vitest'
import { CMSVersion } from './CMSVersion.js'

describe('CMSVersion', () => {
    it('should have correct version numbers', () => {
        expect(CMSVersion.v0).toEqual(0)
        expect(CMSVersion.v1).toEqual(1)
        expect(CMSVersion.v2).toEqual(2)
        expect(CMSVersion.v3).toEqual(3)
        expect(CMSVersion.v4).toEqual(4)
        expect(CMSVersion.v5).toEqual(5)
    })
})
