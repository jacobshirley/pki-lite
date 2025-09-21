import { describe, it, expect, assert } from 'vitest'
import { asn1js } from '../core/PkiBase.js'
import { Attribute } from './Attribute.js'
import { Integer } from '../asn1/Integer.js'
import { Any } from '../asn1/Any.js'

describe('Attribute', () => {
    it('should create an Attribute instance', () => {
        const contentType = new Attribute({
            type: '1.2.840.113549.1.9.3',
            values: ['text/plain'],
        })

        expect(contentType).toBeInstanceOf(Attribute)
        expect(contentType.type.toString()).toBe('1.2.840.113549.1.9.3')
        expect(contentType.values).toHaveLength(1)
        expect(contentType.values[0].asString()).toBe('text/plain')
    })

    it('should create an Attribute with multiple values', () => {
        const keyUsage = new Attribute({
            type: '2.5.29.15',
            values: [
                new Uint8Array([0x03, 0x02, 0x05, 0xa0]), // digitalSignature, nonRepudiation, keyEncipherment
                'Digital Signature, Non-Repudiation, Key Encipherment',
            ],
        })

        expect(keyUsage).toBeInstanceOf(Attribute)
        expect(keyUsage.type.toString()).toBe('2.5.29.15')
        expect(keyUsage.values).toHaveLength(2)
        expect(keyUsage.values[0]).toBeInstanceOf(Any)
        expect(keyUsage.values[1].asString()).toBe(
            'Digital Signature, Non-Repudiation, Key Encipherment',
        )
    })

    it('should convert Attribute to ASN.1 correctly', () => {
        const contentType = new Attribute({
            type: '1.2.840.113549.1.9.3',
            values: ['text/plain'],
        })

        const asn1 = contentType.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect((asn1 as any).valueBlock.value.length).toBe(2)

        // First element should be ObjectIdentifier
        expect((asn1 as any).valueBlock.value[0]).toBeInstanceOf(
            asn1js.ObjectIdentifier,
        )
        assert(
            (asn1 as any).valueBlock.value[0] instanceof
                asn1js.ObjectIdentifier,
        )
        expect((asn1 as any).valueBlock.value[0].toString()).toBe(
            'OBJECT IDENTIFIER : 1.2.840.113549.1.9.3',
        )

        // Second element should be Set containing the values
        expect((asn1 as any).valueBlock.value[1]).toBeInstanceOf(asn1js.Set)
        expect((asn1 as any).valueBlock.value[1].valueBlock.value.length).toBe(
            1,
        )
        // We're not checking the exact type here since the string handling may vary
    })

    it('should handle different value types', () => {
        const mixedAttribute = new Attribute({
            type: '2.5.29.17',
            values: [
                new Uint8Array([1, 2, 3]),
                new Integer({ value: 123 }),
                'test string',
            ],
        })

        const asn1 = mixedAttribute.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect((asn1 as any).valueBlock.value[1].valueBlock.value.length).toBe(
            3,
        )

        // We're checking the value conversion happened but not enforcing specific ASN.1 types
        // as that implementation detail might change
    })

    // Note: Testing fromAsn1 would require mock ASN.1 structures which is more complex
    // and would be implemented in a real test environment

    it('toString snapshot', () => {
        const contentType = new Attribute({
            type: '1.2.840.113549.1.9.3',
            values: ['text/plain'],
        })
        expect(contentType.toString()).toMatchInlineSnapshot(`
          "[Attribute] SEQUENCE :
            OBJECT IDENTIFIER : 1.2.840.113549.1.9.3
            SET :
              PrintableString : 'text/plain'"
        `)
    })

    it('toString snapshot with multiple values', () => {
        const keyUsage = new Attribute({
            type: '2.5.29.15',
            values: [
                new Uint8Array([0x03, 0x02, 0x05, 0xa0]),
                'Digital Signature, Non-Repudiation, Key Encipherment',
            ],
        })

        expect(keyUsage.toString()).toMatchInlineSnapshot(`
          "[Attribute] SEQUENCE :
            OBJECT IDENTIFIER : 2.5.29.15
            SET :
              BIT STRING : 101
              PrintableString : 'Digital Signature, Non-Repudiation, Key Encipherment'"
        `)
    })

    it('toPem snapshot', () => {
        const contentType = new Attribute({
            type: '1.2.840.113549.1.9.3',
            values: ['text/plain'],
        })
        expect(contentType.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ATTRIBUTE-----
          MBkGCSqGSIb3DQEJAzEMEwp0ZXh0L3BsYWlu
          -----END ATTRIBUTE-----"
        `)
    })

    it('toPem snapshot with multiple values', () => {
        const keyUsage = new Attribute({
            type: '2.5.29.15',
            values: [
                new Uint8Array([0x03, 0x02, 0x05, 0xa0]),
                'Digital Signature, Non-Repudiation, Key Encipherment',
            ],
        })
        expect(keyUsage.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ATTRIBUTE-----
          MEEGA1UdDzE6AwIFoBM0RGlnaXRhbCBTaWduYXR1cmUsIE5vbi1SZXB1ZGlhdGlvbiwgS2V5IEVuY2lwaGVybWVudA==
          -----END ATTRIBUTE-----"
        `)
    })
})
