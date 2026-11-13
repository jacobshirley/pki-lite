import { describe, test, expect } from 'vitest'
import { AuthenticatedSafe } from './AuthenticatedSafe.js'
import { der } from '../core/PkiBase.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'

describe('AuthenticatedSafe', () => {
    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = der.integer(42)
        expect(() => AuthenticatedSafe.fromAsn1(notSequence)).toThrow()
    })

    test('fromAsn1 should parse a valid Sequence of ContentInfo', () => {
        // Create proper ContentInfo ASN.1 objects with required ObjectIdentifier
        const contentInfoAsn1_1 = der.sequence([
            der.oid('1.2.840.113549.1.7.1'), // data OID
            der.constructed(0, [der.integer(1)]),
        ])
        const contentInfoAsn1_2 = der.sequence([
            der.oid('1.2.840.113549.1.7.1'), // data OID
            der.constructed(0, [der.integer(2)]),
        ])

        const seq = der.sequence([contentInfoAsn1_1, contentInfoAsn1_2])
        const authenticatedSafe = AuthenticatedSafe.fromAsn1(seq)
        expect(authenticatedSafe.length).toEqual(2)
        expect(authenticatedSafe[0]).toBeInstanceOf(ContentInfo)
        expect(authenticatedSafe[1]).toBeInstanceOf(ContentInfo)
    })

    test('fromDer should parse DER-encoded Sequence', () => {
        // Create a proper ContentInfo ASN.1 with required ObjectIdentifier
        const contentInfoAsn1 = der.sequence([
            der.oid('1.2.840.113549.1.7.1'), // data OID
            der.constructed(0, [der.integer(7)]),
        ])
        const seq = der.sequence([contentInfoAsn1])
        const encoded = seq.encode()

        const authenticatedSafe = AuthenticatedSafe.fromDer(
            new Uint8Array(encoded),
        )
        expect(authenticatedSafe.length).toEqual(1)
        expect(authenticatedSafe[0]).toBeInstanceOf(ContentInfo)
    })
})
