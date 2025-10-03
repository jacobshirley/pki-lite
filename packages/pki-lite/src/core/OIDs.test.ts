import { describe, it, expect } from 'vitest'
import { OIDs } from './OIDs.js'

describe('OIDs', () => {
    it('should have correct values', () => {
        expect(OIDs.RSA.ENCRYPTION).toEqual('1.2.840.113549.1.1.1')
        expect(OIDs.EC.PUBLIC_KEY).toEqual('1.2.840.10045.2.1')
    })
})
