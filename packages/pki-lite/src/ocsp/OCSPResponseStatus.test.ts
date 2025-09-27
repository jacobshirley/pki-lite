import { describe, expect, it } from 'vitest'
import { OCSPResponseStatus } from './OCSPResponseStatus.js'

describe('OCSPResponseStatus', () => {
    it('should have correct status values', () => {
        expect(OCSPResponseStatus.successful.value).toBe(0)
        expect(OCSPResponseStatus.malformedRequest.value).toBe(1)
        expect(OCSPResponseStatus.internalError.value).toBe(2)
        expect(OCSPResponseStatus.tryLater.value).toBe(3)
        expect(OCSPResponseStatus.sigRequired.value).toBe(5)
        expect(OCSPResponseStatus.unauthorized.value).toBe(6)
    })

    it('should have all expected status codes', () => {
        const expectedStatuses = [
            'successful',
            'malformedRequest',
            'internalError',
            'tryLater',
            'sigRequired',
            'unauthorized',
        ]
        const actualStatuses = Object.keys(OCSPResponseStatus)

        expect(actualStatuses.sort()).toEqual(expectedStatuses.sort())
    })
})
