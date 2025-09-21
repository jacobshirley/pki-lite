import { describe, it, expect } from 'vitest'
import { OIDs } from './OIDs.js'

describe('OIDs', () => {
    it('should have correct values', () => {
        expect(OIDs.RSA.ENCRYPTION).toBe('1.2.840.113549.1.1.1')
        expect(OIDs.EC.PUBLIC_KEY).toBe('1.2.840.10045.2.1')
    })
})
