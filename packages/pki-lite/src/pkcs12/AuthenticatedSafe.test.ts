import { describe, test, expect } from 'vitest'
import { AuthenticatedSafe } from './AuthenticatedSafe.js'
import { asn1js } from '../core/PkiBase.js'
import { ContentInfo } from '../pkcs7/ContentInfo.js'

describe('AuthenticatedSafe', () => {
    test('fromAsn1 should throw if not a Sequence', () => {
        const notSequence = new asn1js.Integer({ value: 42 })
        expect(() => AuthenticatedSafe.fromAsn1(notSequence)).toThrow()
    })

    test('fromAsn1 should parse a valid Sequence of ContentInfo', () => {
        // Create proper ContentInfo ASN.1 objects with required ObjectIdentifier
        const contentInfoAsn1_1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }), // data OID
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [new asn1js.Integer({ value: 1 })],
                }),
            ],
        })
        const contentInfoAsn1_2 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }), // data OID
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [new asn1js.Integer({ value: 2 })],
                }),
            ],
        })

        const seq = new asn1js.Sequence({
            value: [contentInfoAsn1_1, contentInfoAsn1_2],
        })
        const authenticatedSafe = AuthenticatedSafe.fromAsn1(seq)
        expect(authenticatedSafe.length).toEqual(2)
        expect(authenticatedSafe[0]).toBeInstanceOf(ContentInfo)
        expect(authenticatedSafe[1]).toBeInstanceOf(ContentInfo)
    })

    test('fromDer should parse DER-encoded Sequence', () => {
        // Create a proper ContentInfo ASN.1 with required ObjectIdentifier
        const contentInfoAsn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }), // data OID
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [new asn1js.Integer({ value: 7 })],
                }),
            ],
        })
        const seq = new asn1js.Sequence({
            value: [contentInfoAsn1],
        })
        const der = seq.toBER(false)

        const authenticatedSafe = AuthenticatedSafe.fromDer(new Uint8Array(der))
        expect(authenticatedSafe.length).toEqual(1)
        expect(authenticatedSafe[0]).toBeInstanceOf(ContentInfo)
    })
})
