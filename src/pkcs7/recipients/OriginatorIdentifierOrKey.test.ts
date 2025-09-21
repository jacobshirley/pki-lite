import { assert, describe, expect, test } from 'vitest'
import { OriginatorIdentifierOrKey } from './OriginatorIdentifierOrKey.js'
import { KeyIdentifier } from './KeyIdentifier.js'
import { asn1js } from '../../core/PkiBase.js'

describe('OriginatorIdentifierOrKey', () => {
    test('can be parsed from ASN.1', () => {
        const keyId = new Uint8Array([1, 2, 3, 4, 5])
        const originator = new OriginatorIdentifierOrKey.SubjectKeyIdentifier({
            bytes: keyId,
        })
        const asn1 = OriginatorIdentifierOrKey.toAsn1(originator)
        const parsed = OriginatorIdentifierOrKey.fromAsn1(asn1)
        expect(parsed).toBeInstanceOf(
            OriginatorIdentifierOrKey.SubjectKeyIdentifier,
        )
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => OriginatorIdentifierOrKey.fromAsn1(asn1)).toThrow(
            /Invalid ASN.1 structure/,
        )
    })
})
