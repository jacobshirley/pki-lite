import { describe, it, expect, assert } from 'vitest'
import { IssuerAndSerialNumber } from './IssuerAndSerialNumber.js'
import { Name } from '../x509/Name.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { asn1js } from '../core/PkiBase.js'

describe('IssuerAndSerialNumber', () => {
    it('should create IssuerAndSerialNumber with number serial', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )

        const issuerAndSerial = new IssuerAndSerialNumber({
            issuer,
            serialNumber: 12345,
        })

        expect(issuerAndSerial.issuer).toBe(issuer)
        expect(issuerAndSerial.serialNumber.toInteger()).toBe(12345)
    })

    it('should create IssuerAndSerialNumber with string serial', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )

        const issuerAndSerial = new IssuerAndSerialNumber({
            issuer,
            serialNumber: '67890',
        })

        expect(issuerAndSerial.issuer).toBe(issuer)
        expect(issuerAndSerial.serialNumber.toString()).toBe('67890')
    })

    it('should convert to ASN.1 structure', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )

        const issuerAndSerial = new IssuerAndSerialNumber({
            issuer,
            serialNumber: 12345,
        })
        const asn1 = issuerAndSerial.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock).toBeDefined()
    })

    it('should have correct properties', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )

        const issuerAndSerial = new IssuerAndSerialNumber({
            issuer,
            serialNumber: 12345,
        })

        expect(issuerAndSerial).toHaveProperty('issuer')
        expect(issuerAndSerial.serialNumber.toInteger()).toBe(12345)
    })

    it('should convert to string', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )

        const issuerAndSerial = new IssuerAndSerialNumber({
            issuer,
            serialNumber: 12345,
        })
        const str = issuerAndSerial.toString()

        expect(typeof str).toBe('string')
        expect(str.length).toBeGreaterThan(0)
    })

    it('should parse from ASN.1 structure', () => {
        // Create an ASN.1 SEQUENCE with issuer and serialNumber
        const serialNumber = 12345
        const asn1 = new asn1js.Sequence({
            value: [
                // Issuer as DN like "CN=Test CA"
                new asn1js.Sequence({
                    value: [
                        new asn1js.Set({
                            value: [
                                new asn1js.Sequence({
                                    value: [
                                        new asn1js.ObjectIdentifier({
                                            value: '2.5.4.3',
                                        }), // CN OID
                                        new asn1js.PrintableString({
                                            value: 'Test CA',
                                        }),
                                    ],
                                }),
                            ],
                        }),
                    ],
                }),
                // Serial Number
                new asn1js.Integer({ value: serialNumber }),
            ],
        })

        const issuerAndSerial = IssuerAndSerialNumber.fromAsn1(asn1)
        expect(issuerAndSerial).toBeInstanceOf(IssuerAndSerialNumber)
        expect(issuerAndSerial.serialNumber.toInteger()).toBe(serialNumber)

        // Check issuer
        expect(issuerAndSerial.issuer).toBeInstanceOf(RDNSequence)
        expect(issuerAndSerial.issuer.length).toBe(1)
        expect(issuerAndSerial.issuer[0][0].type.toString()).toBe('2.5.4.3')
        expect(issuerAndSerial.issuer[0][0].shortName).toBe('CN')
    })

    it('should throw error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a SEQUENCE
        const asn1 = new asn1js.Set({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })

        expect(() => IssuerAndSerialNumber.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    it('should throw error when ASN.1 has wrong number of elements', () => {
        // Create an ASN.1 SEQUENCE with only one element
        const asn1 = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 12345 })],
        })

        expect(() => IssuerAndSerialNumber.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 2 elements',
        )
    })

    it('IssuerAndSerialNumber toString snapshot', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )
        const obj = new IssuerAndSerialNumber({ issuer, serialNumber: 12345 })
        expect(obj.toString()).toMatchInlineSnapshot(`
          "[IssuerAndSerialNumber] SEQUENCE :
            SEQUENCE :
              SET :
                SEQUENCE :
                  OBJECT IDENTIFIER : 2.5.4.3
                  PrintableString : 'Test CA'
            INTEGER : 12345"
        `)
    })

    it('IssuerAndSerialNumber toPem snapshot', () => {
        const issuer = new Name.RDNSequence(
            new RelativeDistinguishedName(
                new AttributeTypeAndValue({
                    type: '2.5.4.3',
                    value: 'Test CA',
                }),
            ),
        )
        const obj = new IssuerAndSerialNumber({ issuer, serialNumber: 12345 })
        expect(obj.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ISSUERANDSERIALNUMBER-----
          MBgwEjEQMA4GA1UEAxMHVGVzdCBDQQICMDk=
          -----END ISSUERANDSERIALNUMBER-----"
        `)
    })
})
