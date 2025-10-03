import { describe, expect, it } from 'vitest'
import { OCSPResponseStatus } from './OCSPResponseStatus.js'

describe('OCSPResponseStatus', () => {
    it('should have correct status values', () => {
        expect(OCSPResponseStatus.successful.value).toEqual(0)
        expect(OCSPResponseStatus.malformedRequest.value).toEqual(1)
        expect(OCSPResponseStatus.internalError.value).toEqual(2)
        expect(OCSPResponseStatus.tryLater.value).toEqual(3)
        expect(OCSPResponseStatus.sigRequired.value).toEqual(5)
        expect(OCSPResponseStatus.unauthorized.value).toEqual(6)
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
