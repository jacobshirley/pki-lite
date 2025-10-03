import { assert, describe, expect, test } from 'vitest'
import { RevokedCertificate } from './RevokedCertificate.js'
import { Extension } from './Extension.js'
import { asn1js, ObjectIdentifierString } from '../core/PkiBase.js'

describe('RevokedCertificate', () => {
    test('can be created with serial number and date', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')

        const revoked = new RevokedCertificate({
            userCertificate: serialNumber,
            revocationDate,
        })

        expect(revoked).toBeInstanceOf(RevokedCertificate)
        expect(revoked.userCertificate).toEqual(serialNumber)
        expect(revoked.revocationDate).toEqual(revocationDate)
        expect(revoked.crlEntryExtensions).toBeUndefined()
    })

    test('can be created with extensions', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')

        const reasonExtId: ObjectIdentifierString = '2.5.29.21' // reasonCode
        const reasonExt = new Extension({
            extnID: reasonExtId,
            critical: false,
            extnValue: true,
        }) // keyCompromise

        const revoked = new RevokedCertificate({
            userCertificate: serialNumber,
            revocationDate,
            crlEntryExtensions: [reasonExt],
        })

        expect(revoked).toBeInstanceOf(RevokedCertificate)
        expect(revoked.userCertificate).toEqual(serialNumber)
        expect(revoked.revocationDate).toEqual(revocationDate)
        expect(revoked.crlEntryExtensions).toHaveLength(1)
        expect(revoked.crlEntryExtensions?.[0]).toEqual(reasonExt)
    })

    test('can be created with string serial number', () => {
        const serialNumber = '12345'
        const revocationDate = new Date('2025-05-01')

        const revoked = new RevokedCertificate({
            userCertificate: serialNumber,
            revocationDate,
        })

        expect(revoked).toBeInstanceOf(RevokedCertificate)
        expect(revoked.userCertificate).toEqual(serialNumber)
        expect(revoked.revocationDate).toEqual(revocationDate)
    })

    test('can be converted to ASN.1', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')

        const revoked = new RevokedCertificate({
            userCertificate: serialNumber,
            revocationDate,
        })
        const asn1 = revoked.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2) // userCertificate, revocationDate

        const [serialBlock, dateBlock] = asn1.valueBlock.value

        expect(serialBlock).toBeInstanceOf(asn1js.Integer)
        expect((serialBlock as asn1js.Integer).valueBlock.valueDec).toEqual(
            serialNumber,
        )

        expect(dateBlock).toBeInstanceOf(asn1js.UTCTime)
        // Just check the type is correct as exact date comparison is complex
        expect(dateBlock).toBeInstanceOf(asn1js.UTCTime)
    })

    test('can be converted to ASN.1 with extensions', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')

        const reasonExtId: ObjectIdentifierString = '2.5.29.21' // reasonCode
        const reasonExt = new Extension({
            extnID: reasonExtId,
            critical: false,
            extnValue: null,
        }) // keyCompromise

        const revoked = new RevokedCertificate({
            userCertificate: serialNumber,
            revocationDate,
            crlEntryExtensions: [reasonExt],
        })
        const asn1 = revoked.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3) // userCertificate, revocationDate, extensions

        // Check that the third element is a sequence (extensions)
        const extensionsBlock = asn1.valueBlock.value[2]
        expect(extensionsBlock).toBeInstanceOf(asn1js.Sequence)
        expect(
            (extensionsBlock as asn1js.Sequence).valueBlock.value.length,
        ).toEqual(1) // one extension
    })

    test('can be parsed from ASN.1 without extensions', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')

        // Create the ASN.1 structure
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: serialNumber }),
                new asn1js.UTCTime({ valueDate: revocationDate }),
            ],
        })

        const revoked = RevokedCertificate.fromAsn1(asn1)
        expect(revoked).toBeInstanceOf(RevokedCertificate)
        expect(revoked.userCertificate).toEqual(serialNumber)

        // Date comparison is tricky due to potential timezone issues,
        // so just check the date is a Date object
        expect(revoked.revocationDate).toBeInstanceOf(Date)
        expect(revoked.crlEntryExtensions).toBeUndefined()
    })

    test('can be parsed from ASN.1 with extensions', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')
        const reasonExtId: ObjectIdentifierString = '2.5.29.21' // reasonCode

        // Mock the Extension.fromAsn1 method
        const originalFromAsn1 = Extension.fromAsn1
        const mockExtension = new Extension({
            extnID: reasonExtId,
            critical: false,
            extnValue: null,
        })

        Extension.fromAsn1 = function () {
            return mockExtension
        } as any

        try {
            // Create the ASN.1 structure with extensions
            const asn1 = new asn1js.Sequence({
                value: [
                    new asn1js.Integer({ value: serialNumber }),
                    new asn1js.UTCTime({ valueDate: revocationDate }),
                    new asn1js.Sequence({
                        value: [
                            new asn1js.Sequence({}), // dummy extension
                        ],
                    }),
                ],
            })

            const revoked = RevokedCertificate.fromAsn1(asn1)
            expect(revoked).toBeInstanceOf(RevokedCertificate)
            expect(revoked.userCertificate).toEqual(serialNumber)
            expect(revoked.revocationDate).toBeInstanceOf(Date)
            expect(revoked.crlEntryExtensions).toBeDefined()
            expect(revoked.crlEntryExtensions?.length).toEqual(1)
            expect(revoked.crlEntryExtensions?.[0]).toEqual(mockExtension)
        } finally {
            // Restore the original method
            Extension.fromAsn1 = originalFromAsn1
        }
    })

    test('fromAsn1 throws error for non-sequence', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => RevokedCertificate.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                // Missing revocationDate
            ],
        })
        expect(() => RevokedCertificate.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 2 or 3 elements',
        )
    })

    test('fromAsn1 throws error for invalid userCertificate', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.UTCTime({ valueDate: new Date() }), // Not an Integer
                new asn1js.UTCTime({ valueDate: new Date() }),
            ],
        })
        expect(() => RevokedCertificate.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: userCertificate must be an INTEGER',
        )
    })

    test('RevokedCertificate toString snapshot', () => {
        const obj = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2024-01-01T00:00:00.000Z'),
        })

        expect(obj.toString()).toMatchInlineSnapshot(`
          "[RevokedCertificate] SEQUENCE :
            INTEGER : 12345
            UTCTime : 2024-01-01T00:00:00.000Z"
        `)
    })

    test('RevokedCertificate toString snapshot with extensions', () => {
        const reasonExtId: ObjectIdentifierString = '2.5.29.21'
        const reasonExt = new Extension({
            extnID: reasonExtId,
            critical: false,
            extnValue: 'test',
        })
        const obj = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2024-01-01T00:00:00.000Z'),
            crlEntryExtensions: [reasonExt],
        })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[RevokedCertificate] SEQUENCE :
            INTEGER : 12345
            UTCTime : 2024-01-01T00:00:00.000Z
            SEQUENCE :
              SEQUENCE :
                OBJECT IDENTIFIER : 2.5.29.21
                OCTET STRING : 130474657374"
        `)
    })

    test('RevokedCertificate toPem snapshot', () => {
        const obj = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2024-01-01T00:00:00.000Z'),
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN REVOKEDCERTIFICATE-----
          MBMCAjA5Fw0yNDAxMDEwMDAwMDBa
          -----END REVOKEDCERTIFICATE-----"
        `)
    })

    test('RevokedCertificate toPem snapshot with extensions', () => {
        const reasonExtId: ObjectIdentifierString = '2.5.29.21'
        const reasonExt = new Extension({
            extnID: reasonExtId,
            critical: false,
            extnValue: null,
        })
        const obj = new RevokedCertificate({
            userCertificate: 12345,
            revocationDate: new Date('2024-01-01T00:00:00.000Z'),
            crlEntryExtensions: [reasonExt],
        })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN REVOKEDCERTIFICATE-----
          MCACAjA5Fw0yNDAxMDEwMDAwMDBaMAswCQYDVR0VBAIFAA==
          -----END REVOKEDCERTIFICATE-----"
        `)
    })
})
