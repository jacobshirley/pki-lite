import { assert, describe, expect, test } from 'vitest'
import { SubjectAltName } from './SubjectAltName.js'
import {
    dNSName,
    rfc822Name,
    uniformResourceIdentifier,
    iPAddress,
} from '../GeneralName.js'
import * as asn1js from 'asn1js'

describe('SubjectAltName', () => {
    test('should create empty SubjectAltName', () => {
        const subjectAltName = new SubjectAltName()

        expect(subjectAltName).toBeInstanceOf(SubjectAltName)
        expect(subjectAltName.length).toBe(0)
    })

    test('should create SubjectAltName with DNS names', () => {
        const dnsName1 = new dNSName({ value: 'example.com' })
        const dnsName2 = new dNSName({ value: 'www.example.com' })

        const subjectAltName = new SubjectAltName(dnsName1, dnsName2)

        expect(subjectAltName.length).toBe(2)
        expect(subjectAltName[0]).toBe(dnsName1)
        expect(subjectAltName[1]).toBe(dnsName2)
    })

    test('should create SubjectAltName with mixed GeneralName types', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const emailName = new rfc822Name({ value: 'admin@example.com' })
        const uri = new uniformResourceIdentifier({
            value: 'https://example.com',
        })

        const subjectAltName = new SubjectAltName(dnsName, emailName, uri)

        expect(subjectAltName.length).toBe(3)
        expect(subjectAltName[0]).toBe(dnsName)
        expect(subjectAltName[1]).toBe(emailName)
        expect(subjectAltName[2]).toBe(uri)
    })

    test('should create SubjectAltName with IP addresses', () => {
        const ipv4 = new iPAddress({ bytes: new Uint8Array([192, 168, 1, 1]) })
        const ipv6 = new iPAddress({
            bytes: new Uint8Array([
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00,
                0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
            ]),
        })

        const subjectAltName = new SubjectAltName(ipv4, ipv6)

        expect(subjectAltName.length).toBe(2)
        expect(subjectAltName[0]).toBe(ipv4)
        expect(subjectAltName[1]).toBe(ipv6)
    })

    test('should convert to ASN.1 structure', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const emailName = new rfc822Name({ value: 'test@example.com' })

        const subjectAltName = new SubjectAltName(dnsName, emailName)
        const asn1 = subjectAltName.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)
    })

    test('should parse from ASN.1 structure with DNS names', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
                    value: [new asn1js.IA5String({ value: 'example.com' })],
                }),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
                    value: [new asn1js.IA5String({ value: 'www.example.com' })],
                }),
            ],
        })

        const subjectAltName = SubjectAltName.fromAsn1(asn1)

        expect(subjectAltName).toBeInstanceOf(SubjectAltName)
        expect(subjectAltName.length).toBe(2)
        expect(subjectAltName[0]).toBeInstanceOf(dNSName)
        expect(subjectAltName[1]).toBeInstanceOf(dNSName)
        expect(subjectAltName[0].toString()).toBe('example.com')
        expect(subjectAltName[1].toString()).toBe('www.example.com')
    })

    test('should parse from ASN.1 structure with mixed types', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
                    value: [new asn1js.IA5String({ value: 'example.com' })],
                }),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 }, // [1] rfc822Name
                    value: [
                        new asn1js.IA5String({ value: 'admin@example.com' }),
                    ],
                }),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 6 }, // [6] uniformResourceIdentifier
                    value: [
                        new asn1js.IA5String({ value: 'https://example.com' }),
                    ],
                }),
            ],
        })

        const subjectAltName = SubjectAltName.fromAsn1(asn1)

        expect(subjectAltName.length).toBe(3)
        expect(subjectAltName[0]).toBeInstanceOf(dNSName)
        expect(subjectAltName[1]).toBeInstanceOf(rfc822Name)
        expect(subjectAltName[2]).toBeInstanceOf(uniformResourceIdentifier)
    })

    test('fromAsn1 should throw error for invalid ASN.1 structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => SubjectAltName.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for SubjectAltName',
        )
    })

    test('should handle empty ASN.1 sequence', () => {
        const asn1 = new asn1js.Sequence({ value: [] })

        const subjectAltName = SubjectAltName.fromAsn1(asn1)

        expect(subjectAltName).toBeInstanceOf(SubjectAltName)
        expect(subjectAltName.length).toBe(0)
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const dnsName = new dNSName({ value: 'test.example.com' })
        const emailName = new rfc822Name({ value: 'test@example.com' })
        const uri = new uniformResourceIdentifier({
            value: 'https://test.example.com',
        })

        const original = new SubjectAltName(dnsName, emailName, uri)
        const asn1 = original.toAsn1()
        const decoded = SubjectAltName.fromAsn1(asn1)

        expect(decoded.length).toBe(original.length)
        expect(decoded[0]).toBeInstanceOf(dNSName)
        expect(decoded[1]).toBeInstanceOf(rfc822Name)
        expect(decoded[2]).toBeInstanceOf(uniformResourceIdentifier)
        expect(decoded[0].toString()).toBe('test.example.com')
        expect(decoded[1].toString()).toBe('test@example.com')
        expect(decoded[2].toString()).toBe('https://test.example.com')
    })

    test('should support common certificate use cases', () => {
        // Web server certificate with multiple domains
        const webServerSAN = new SubjectAltName(
            new dNSName({ value: 'example.com' }),
            new dNSName({ value: 'www.example.com' }),
            new dNSName({ value: 'mail.example.com' }),
            new dNSName({ value: 'api.example.com' }),
        )

        expect(webServerSAN.length).toBe(4)
        expect(webServerSAN.every((name) => name instanceof dNSName)).toBe(true)

        // Email certificate
        const emailSAN = new SubjectAltName(
            new rfc822Name({ value: 'user@example.com' }),
            new rfc822Name({ value: 'admin@example.com' }),
        )

        expect(emailSAN.length).toBe(2)
        expect(emailSAN.every((name) => name instanceof rfc822Name)).toBe(true)

        // Service certificate with IP addresses
        const serviceSAN = new SubjectAltName(
            new iPAddress({ bytes: new Uint8Array([10, 0, 0, 1]) }),
            new iPAddress({ bytes: new Uint8Array([10, 0, 0, 2]) }),
            new dNSName({ value: 'service.internal' }),
        )

        expect(serviceSAN.length).toBe(3)
        expect(serviceSAN[0]).toBeInstanceOf(iPAddress)
        expect(serviceSAN[1]).toBeInstanceOf(iPAddress)
        expect(serviceSAN[2]).toBeInstanceOf(dNSName)
    })
})
