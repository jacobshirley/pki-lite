import { describe, expect, test } from 'vitest'
import { asn1js } from '../core/PkiBase.js'
import { Attributes } from './Attributes.js'
import { Attribute } from './Attribute.js'
import { OIDs } from '../core/OIDs.js'

describe('Attributes', () => {
    test('fromAsn1 should parse ASN.1 structure correctly', () => {
        const test = new Attribute({
            type: OIDs.CURVES.ED25519,
            values: ['value1', 'value2'],
        })
        const asn1 = new asn1js.Set({
            value: [test.toAsn1()],
        })

        const attributes = Attributes.fromAsn1(asn1)

        expect(attributes).toBeInstanceOf(Attributes)
        expect(attributes).toHaveLength(1)
        expect(attributes[0]).toEqual(test)
    })
})
