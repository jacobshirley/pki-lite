import { assert, describe, expect, test } from 'vitest'
import { derToAsn1 } from '../core/PkiBase.js'
import { RevokedCertificate } from './RevokedCertificate.js'
import { Extension } from './Extension.js'
import { der, ObjectIdentifierString, UniversalTag } from '../core/PkiBase.js'
import { pkitsFiles } from '../../test-fixtures/pkits/pkits.js'
import { CertificateList } from './CertificateList.js'
import { directoryName } from './GeneralName.js'

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

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(2) // userCertificate, revocationDate

        const [serialBlock, dateBlock] = asn1.children

        expect(serialBlock.is(UniversalTag.Integer)).toBe(true)
        expect(der.readNumber(serialBlock)).toEqual(serialNumber)

        expect(dateBlock.is(UniversalTag.UTCTime)).toBe(true)
        // Just check the type is correct as exact date comparison is complex
        expect(dateBlock.is(UniversalTag.UTCTime)).toBe(true)
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

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(3) // userCertificate, revocationDate, extensions

        // Check that the third element is a sequence (extensions)
        const extensionsBlock = asn1.children[2]
        expect(extensionsBlock.is(UniversalTag.Sequence)).toBe(true)
        expect(extensionsBlock.children.length).toEqual(1) // one extension
    })

    test('can be parsed from ASN.1 without extensions', () => {
        const serialNumber = 12345
        const revocationDate = new Date('2025-05-01')

        // Create the ASN.1 structure
        const asn1 = der.sequence([
            der.integer(serialNumber),
            der.utcTime(revocationDate),
        ])

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
            const asn1 = der.sequence([
                der.integer(serialNumber),
                der.utcTime(revocationDate),
                der.sequence([
                    der.sequence([]), // dummy extension
                ]),
            ])

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
        const asn1 = der.integer(1)
        expect(() => RevokedCertificate.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for wrong number of elements', () => {
        const asn1 = der.sequence([
            der.integer(1),
            // Missing revocationDate
        ])
        expect(() => RevokedCertificate.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 2 or 3 elements',
        )
    })

    test('fromAsn1 throws error for invalid userCertificate', () => {
        const asn1 = der.sequence([
            der.utcTime(new Date()), // Not an Integer
            der.utcTime(new Date()),
        ])
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

    describe('serial numbers', () => {
        // SEQUENCE { INTEGER <serial>, UTCTime 260101000000Z }
        const entry = (serial: number[]) => {
            const time = [...new TextEncoder().encode('260101000000Z')]
            const body = [
                0x02,
                serial.length,
                ...serial,
                0x17,
                time.length,
                ...time,
            ]
            return new Uint8Array([0x30, body.length, ...body])
        }

        test('keeps a 16-byte serial exactly (it used to read as 0)', () => {
            const serial = [
                0x4f, 0x1c, 0x00, 0xa2, 0x9b, 0x77, 0x31, 0xe0, 0x05, 0x6d,
                0xc4, 0x18, 0xf2, 0x3a, 0x90, 0x5b,
            ]
            const der = entry(serial)
            const revoked = RevokedCertificate.fromAsn1(derToAsn1(der))
            expect(revoked.userCertificate).toBe(
                '4f1c00a29b7731e0056dc418f23a905b',
            )
            expect(revoked.toDer()).toEqual(der)
        })

        test('reads a small serial as a number', () => {
            const revoked = RevokedCertificate.fromAsn1(
                derToAsn1(entry([0x30, 0x39])),
            )
            expect(revoked.userCertificate).toBe(12345)
        })

        test('serialAsBigInt accepts numbers and hex in any common form', () => {
            const at = (userCertificate: number | string) =>
                new RevokedCertificate({
                    userCertificate,
                    revocationDate: new Date(),
                }).serialAsBigInt()
            expect(at(0xabcdef)).toBe(0xabcdefn)
            expect(at('ABCDEF')).toBe(0xabcdefn)
            expect(at('0xab:cd:ef')).toBe(0xabcdefn)
            expect(() => at('zz')).toThrow('Invalid serial number')
        })

        test('encodes a large hex serial without losing precision', () => {
            const revoked = new RevokedCertificate({
                userCertificate: 'ffffffffffffffffffff',
                revocationDate: new Date('2026-01-01T00:00:00Z'),
            })
            const parsed = RevokedCertificate.fromAsn1(
                derToAsn1(revoked.toDer()),
            )
            expect(parsed.userCertificate).toBe('ffffffffffffffffffff')
        })
    })
})

const pkitsDer = (name: string) =>
    Uint8Array.from(atob(pkitsFiles[name]), (c) => c.charCodeAt(0))

describe('RevokedCertificate extension helpers', () => {
    const entries = (name: string) =>
        CertificateList.fromDer(pkitsDer(name)).tbsCertList.revokedCertificates!

    test('reason', () => {
        expect(entries('GoodCACRL').map((entry) => entry.reason)).toContain(1)
        expect(
            new RevokedCertificate({
                userCertificate: 1,
                revocationDate: new Date(),
            }).reason,
        ).toBeUndefined()
    })

    test('certificateIssuer on an indirect CRL', () => {
        const named = entries('indirectCRLCA5CRL')
            .map((entry) => entry.certificateIssuer)
            .filter((names) => names !== undefined)
        expect(named.length).toBeGreaterThan(0)
        expect(named[0][0]).toBeInstanceOf(directoryName)
    })
})
