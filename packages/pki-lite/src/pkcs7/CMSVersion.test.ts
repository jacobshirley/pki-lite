import { describe, it, expect } from 'vitest'
import { CMSVersion } from './CMSVersion.js'

describe('CMSVersion', () => {
    it('should have correct version numbers', () => {
        expect(CMSVersion.v0).toBe(0)
        expect(CMSVersion.v1).toBe(1)
        expect(CMSVersion.v2).toBe(2)
        expect(CMSVersion.v3).toBe(3)
        expect(CMSVersion.v4).toBe(4)
        expect(CMSVersion.v5).toBe(5)
    })
})
