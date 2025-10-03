import { assert, describe, expect, test } from 'vitest'
import { OtherKeyAttribute } from './OtherKeyAttribute.js'
import { asn1js } from '../../core/PkiBase.js'
import { Any } from '../../asn1/Any.js'

describe('OtherKeyAttribute', () => {
    test('can be created with only keyAttrId', () => {
        const keyAttrId = '1.2.840.113549.1.9.52' // CMSAlgorithmProtection
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId })

        expect(otherKeyAttr).toBeInstanceOf(OtherKeyAttribute)
        expect(otherKeyAttr.keyAttrId.toString()).toEqual(keyAttrId)
        expect(otherKeyAttr.keyAttr).toBeUndefined()
    })

    test('can be created with keyAttrId and keyAttr', () => {
        const keyAttrId = '1.2.840.113549.1.9.52' // CMSAlgorithmProtection
        const keyAttr = new Any({
            derBytes: new asn1js.OctetString({
                valueHex: new Uint8Array([1, 2, 3, 4]),
            }).toBER(),
        })
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId, keyAttr })

        expect(otherKeyAttr).toBeInstanceOf(OtherKeyAttribute)
        expect(otherKeyAttr.keyAttrId.toString()).toEqual(keyAttrId)
        expect(otherKeyAttr.keyAttr).toEqual(keyAttr)
    })

    test('can be converted to ASN.1 with only keyAttrId', () => {
        const keyAttrId = '1.2.840.113549.1.9.52' // CMSAlgorithmProtection
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId })
        const asn1 = otherKeyAttr.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(1)

        const keyAttrIdBlock = asn1.valueBlock.value[0]
        assert(keyAttrIdBlock instanceof asn1js.ObjectIdentifier)
        expect(keyAttrIdBlock.valueBlock.toString()).toContain(keyAttrId)
    })

    test('can be converted to ASN.1 with keyAttrId and keyAttr', () => {
        const keyAttrId = '1.2.840.113549.1.9.52' // CMSAlgorithmProtection
        const keyAttr = new Any({
            derBytes: new asn1js.OctetString({
                valueHex: new Uint8Array([1, 2, 3, 4]),
            }).toBER(),
        })
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId, keyAttr })
        const asn1 = otherKeyAttr.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)

        const keyAttrIdBlock = asn1.valueBlock.value[0]
        assert(keyAttrIdBlock instanceof asn1js.ObjectIdentifier)
        expect(keyAttrIdBlock.valueBlock.toString()).toContain(keyAttrId)

        const keyAttrBlock = asn1.valueBlock.value[1]
        assert(keyAttrBlock instanceof asn1js.OctetString)
    })

    test('can be parsed from ASN.1 with only keyAttrId', () => {
        const keyAttrId = '1.2.840.113549.1.9.52' // CMSAlgorithmProtection
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId })
        const asn1 = otherKeyAttr.toAsn1()
        const parsed = OtherKeyAttribute.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(OtherKeyAttribute)
        expect(parsed.keyAttrId.toString()).toEqual(keyAttrId)
    })

    test('can be parsed from ASN.1 with keyAttrId and keyAttr', () => {
        const keyAttrId = '1.2.840.113549.1.9.52' // CMSAlgorithmProtection
        const keyAttr = new Any({ derBytes: 'test' })
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId, keyAttr })
        const asn1 = otherKeyAttr.toAsn1()
        const parsed = OtherKeyAttribute.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(OtherKeyAttribute)
        expect(parsed.keyAttrId.toString()).toEqual(keyAttrId)
        expect(parsed.keyAttr).toBeInstanceOf(Any)
    })

    test('parseKeyAttrAs can parse the key attribute as a specific type', () => {
        // Create a mock class with a fromAsn1 method
        class MockClass {
            value: any
            constructor(value: any) {
                this.value = value
            }
            static fromAsn1(asn1: any) {
                return new MockClass('parsed')
            }
        }

        const keyAttrId = '1.2.840.113549.1.9.52'
        const keyAttr = new Any({
            derBytes: new asn1js.OctetString({
                valueHex: new Uint8Array([1, 2, 3, 4]),
            }).toBER(),
        })
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId, keyAttr })

        const result = otherKeyAttr.parseKeyAttrAs(MockClass)
        expect(result).toBeInstanceOf(MockClass)
        expect(result.value).toEqual('parsed')
    })

    test('parseKeyAttrAs throws error if keyAttr is not set', () => {
        const keyAttrId = '1.2.840.113549.1.9.52'
        const otherKeyAttr = new OtherKeyAttribute({ keyAttrId })

        // Create a mock class with a fromAsn1 method
        class MockClass {
            static fromAsn1(asn1: any) {
                return new MockClass()
            }
        }

        expect(() => otherKeyAttr.parseKeyAttrAs(MockClass)).toThrow(
            'Key attribute is not set',
        )
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => OtherKeyAttribute.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for OtherKeyAttribute',
        )
    })

    test('throws error on invalid ASN.1 structure element count', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.52' }),
                new asn1js.OctetString({ valueHex: new Uint8Array([1]) }),
                new asn1js.OctetString({ valueHex: new Uint8Array([2]) }),
            ],
        })
        expect(() => OtherKeyAttribute.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 1-2 elements, got 3',
        )
    })

    test('throws error on invalid keyAttrId type', () => {
        const asn1 = new asn1js.Sequence({
            value: [new asn1js.OctetString({ valueHex: new Uint8Array([1]) })],
        })
        expect(() => OtherKeyAttribute.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected ObjectIdentifier for keyAttrId',
        )
    })
})
