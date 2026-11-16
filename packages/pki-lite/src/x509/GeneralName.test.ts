import { assert, describe, expect, test } from 'vitest'
import {
    AnotherName,
    EDIPartyName,
    GeneralName,
    GeneralNames,
    dNSName,
    rfc822Name,
    uniformResourceIdentifier,
    iPAddress,
    registeredID,
    directoryName,
    otherName,
    ediPartyName,
} from './GeneralName.js'
import { UTF8String } from '../asn1/UTF8String.js'
import { PrintableString } from '../asn1/PrintableString.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { RDNSequence } from './RDNSequence.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from './AttributeTypeAndValue.js'
import { OIDs } from '../core/OIDs.js'
import * as asn1js from 'asn1js'
import { DirectoryString } from './DirectoryString.js'
import { derToAsn1 } from '../core/PkiBase.js'

describe('AnotherName', () => {
    test('should create AnotherName with string typeID', () => {
        const anotherName = new AnotherName({
            typeID: '1.2.3.4.5',
            value: new UTF8String({ value: 'test value' }),
        })

        expect(anotherName.typeID).toBeInstanceOf(ObjectIdentifier)
        expect(anotherName.typeID.value).toEqual('1.2.3.4.5')
        expect(anotherName.value).toBeDefined()
    })

    test('should create AnotherName with ObjectIdentifier typeID', () => {
        const oid = new ObjectIdentifier({ value: '1.2.3.4.5' })
        const anotherName = new AnotherName({
            typeID: oid,
            value: new UTF8String({ value: 'test value' }),
        })

        expect(anotherName.typeID.value).toEqual(oid.value)
    })

    test('should convert to ASN.1 structure', () => {
        const anotherName = new AnotherName({
            typeID: '1.2.3.4.5',
            value: new UTF8String({ value: 'test' }),
        })

        const asn1 = anotherName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)
    })

    test('should parse from ASN.1 structure', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.3.4.5' }),
                new asn1js.Utf8String({ value: 'test value' }),
            ],
        })

        const anotherName = AnotherName.fromAsn1(asn1)
        expect(anotherName.typeID.value).toEqual('1.2.3.4.5')
    })

    test('fromAsn1 should throw error for invalid structure', () => {
        const invalidAsn1 = new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: '1.2.3' })], // Missing value
        })

        expect(() => AnotherName.fromAsn1(invalidAsn1)).toThrow(
            'Invalid AnotherName ASN.1 structure',
        )
    })
})

describe('DirectoryString', () => {
    test('should create DirectoryString from UTF8String', () => {
        const utf8String = new UTF8String({ value: 'Test String' })
        const asn1 = DirectoryString.toAsn1(utf8String)

        expect(asn1).toBeInstanceOf(asn1js.Utf8String)
    })

    test('should create DirectoryString from PrintableString', () => {
        const printableString = new PrintableString({ value: 'Test String' })
        const asn1 = DirectoryString.toAsn1(printableString)

        expect(asn1).toBeInstanceOf(asn1js.PrintableString)
    })

    test('should parse DirectoryString from ASN.1', () => {
        const asn1 = new asn1js.Utf8String({ value: 'Test String' })
        const directoryString = DirectoryString.fromAsn1(asn1)

        expect(directoryString).toBeInstanceOf(UTF8String)
        expect(directoryString.toString()).toEqual('Test String')
    })

    test('fromAsn1 should throw error for invalid ASN.1', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => DirectoryString.fromAsn1(invalidAsn1)).toThrow(
            'Invalid DirectoryString ASN.1 structure',
        )
    })
})

describe('EDIPartyName', () => {
    test('should create EDIPartyName with string partyName', () => {
        const ediPartyName = new EDIPartyName({
            partyName: 'Test Party',
        })

        expect(ediPartyName.partyName).toBeInstanceOf(UTF8String)
        expect(ediPartyName.partyName.toString()).toEqual('Test Party')
        expect(ediPartyName.nameAssigner).toBeUndefined()
    })

    test('should create EDIPartyName with nameAssigner', () => {
        const ediPartyName = new EDIPartyName({
            nameAssigner: 'Test Assigner',
            partyName: 'Test Party',
        })

        expect(ediPartyName.nameAssigner).toBeInstanceOf(UTF8String)
        expect(ediPartyName.nameAssigner!.toString()).toEqual('Test Assigner')
        expect(ediPartyName.partyName.toString()).toEqual('Test Party')
    })

    test('should convert to ASN.1 structure', () => {
        const ediPartyName = new EDIPartyName({
            nameAssigner: 'Assigner',
            partyName: 'Party',
        })

        const asn1 = ediPartyName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2) // nameAssigner + partyName
    })
})

const toHex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('GeneralName types', () => {
    test('dNSName should work correctly', () => {
        const dnsName = new dNSName({ value: 'example.com' })

        expect(dnsName.toString()).toEqual('example.com')

        const asn1 = dnsName.toAsn1()
        // IMPLICIT tagging: a primitive context-specific value, not a wrapper
        expect(asn1.idBlock.isConstructed).toBe(false)
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(2) // [2]
        expect(toHex(dnsName.toDer())).toEqual('820b6578616d706c652e636f6d')
    })

    test('rfc822Name should work correctly', () => {
        const emailName = new rfc822Name({ value: 'test@example.com' })

        expect(emailName.toString()).toEqual('test@example.com')

        const asn1 = emailName.toAsn1()
        // IMPLICIT tagging: a primitive context-specific value, not a wrapper
        expect(asn1.idBlock.isConstructed).toBe(false)
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(1) // [1]
        expect(toHex(emailName.toDer())).toEqual(
            '811074657374406578616d706c652e636f6d',
        )
    })

    test('uniformResourceIdentifier should work correctly', () => {
        const uri = new uniformResourceIdentifier({
            value: 'https://example.com',
        })

        expect(uri.toString()).toEqual('https://example.com')

        const asn1 = uri.toAsn1()
        // IMPLICIT tagging: a primitive context-specific value, not a wrapper
        expect(asn1.idBlock.isConstructed).toBe(false)
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(6) // [6]
        expect(toHex(uri.toDer())).toEqual(
            '861368747470733a2f2f6578616d706c652e636f6d',
        )
    })

    test('iPAddress should work correctly', () => {
        // IPv4 address: 192.168.1.1
        const ipBytes = new Uint8Array([192, 168, 1, 1])
        const ipAddress = new iPAddress({ bytes: ipBytes })

        expect(ipAddress.bytes).toEqual(ipBytes)

        const asn1 = ipAddress.toAsn1()
        // IMPLICIT tagging: a primitive context-specific value, not a wrapper
        expect(asn1.idBlock.isConstructed).toBe(false)
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(7) // [7]
        expect(toHex(ipAddress.toDer())).toEqual('8704c0a80101')
    })

    test('registeredID should work correctly', () => {
        const regId = new registeredID({ value: '1.2.3.4.5.6' })

        expect(regId.value).toEqual('1.2.3.4.5.6')

        const asn1 = regId.toAsn1()
        // IMPLICIT tagging: a primitive context-specific value, not a wrapper
        expect(asn1.idBlock.isConstructed).toBe(false)
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(8) // [8]
        expect(toHex(regId.toDer())).toEqual('88052a03040506')
    })

    test('directoryName should work correctly', () => {
        const rdnSeq = new RDNSequence()
        const rdn = new RelativeDistinguishedName()
        const cnAttr = new AttributeTypeAndValue({
            type: OIDs.DN.CN,
            value: 'Test Subject',
        })
        rdn.push(cnAttr)
        rdnSeq.push(rdn)

        const dirName = new directoryName(...rdnSeq)

        expect(dirName.length).toEqual(1)

        const asn1 = dirName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(4) // [4]
    })
})

describe('GeneralName Choice', () => {
    test('should convert GeneralName to ASN.1', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const asn1 = GeneralName.toAsn1(dnsName)

        expect(asn1.idBlock.isConstructed).toBe(false)
        expect(asn1.idBlock.tagNumber).toEqual(2) // dNSName tag
    })

    test('should parse GeneralName from ASN.1 dNSName', () => {
        const asn1 = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
            value: [new asn1js.IA5String({ value: 'example.com' })],
        })

        const generalName = GeneralName.fromAsn1(asn1)
        expect(generalName).toBeInstanceOf(dNSName)
        expect(generalName.toString()).toEqual('example.com')
    })

    test('should parse GeneralName from ASN.1 rfc822Name', () => {
        const asn1 = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 }, // [1] rfc822Name
            value: [new asn1js.IA5String({ value: 'test@example.com' })],
        })

        const generalName = GeneralName.fromAsn1(asn1)
        expect(generalName).toBeInstanceOf(rfc822Name)
        expect(generalName.toString()).toEqual('test@example.com')
    })

    test('fromAsn1 should throw error for unknown tag number', () => {
        const asn1 = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 99 }, // Invalid tag
            value: [],
        })

        expect(() => GeneralName.fromAsn1(asn1)).toThrow(
            'Invalid GeneralName ASN.1 structure: unknown tag number 99',
        )
    })

    test('fromAsn1 should throw error for non-constructed type', () => {
        const asn1 = new asn1js.Integer({ value: 123 })

        expect(() => GeneralName.fromAsn1(asn1)).toThrow(
            'Invalid GeneralName ASN.1 structure: not a constructed or primitive type',
        )
    })
})

describe('GeneralNames', () => {
    test('should create empty GeneralNames', () => {
        const generalNames = new GeneralNames()

        expect(generalNames.length).toEqual(0)
    })

    test('should create GeneralNames with multiple names', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const emailName = new rfc822Name({ value: 'test@example.com' })

        const generalNames = new GeneralNames(dnsName, emailName)

        expect(generalNames.length).toEqual(2)
        expect(generalNames[0]).toEqual(dnsName)
        expect(generalNames[1]).toEqual(emailName)
    })

    test('should convert to ASN.1 sequence', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const emailName = new rfc822Name({ value: 'test@example.com' })
        const generalNames = new GeneralNames(dnsName, emailName)

        const asn1 = generalNames.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)
    })

    test('should parse from ASN.1 sequence', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
                    value: [new asn1js.IA5String({ value: 'example.com' })],
                }),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 }, // [1] rfc822Name
                    value: [
                        new asn1js.IA5String({ value: 'test@example.com' }),
                    ],
                }),
            ],
        })

        const generalNames = GeneralNames.fromAsn1(asn1)
        expect(generalNames.length).toEqual(2)
        expect(generalNames[0]).toBeInstanceOf(dNSName)
        expect(generalNames[1]).toBeInstanceOf(rfc822Name)
    })

    test('fromAsn1 should throw error for invalid ASN.1', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 123 })

        expect(() => GeneralNames.fromAsn1(invalidAsn1)).toThrow(
            'Invalid GeneralNames ASN.1 structure',
        )
    })
})

describe('GeneralName encoding (RFC 5280, IMPLICIT TAGS)', () => {
    const parse = (hex: string) =>
        GeneralName.fromAsn1(
            derToAsn1(
                new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16))),
            ),
        )

    test('parses the DER OpenSSL writes for each alternative', () => {
        expect(parse('820b6578616d706c652e636f6d')).toBeInstanceOf(dNSName)
        expect(String(parse('820b6578616d706c652e636f6d'))).toBe('example.com')
        expect(parse('8704c0a80101')).toBeInstanceOf(iPAddress)
        expect(parse('88052a03040506')).toBeInstanceOf(registeredID)
        expect((parse('88052a03040506') as registeredID).value).toBe(
            '1.2.3.4.5.6',
        )
    })

    test('still parses the explicit forms written by earlier versions', () => {
        // [2] { IA5String "example.com" }
        const legacy = parse('a20d160b6578616d706c652e636f6d')
        expect(legacy).toBeInstanceOf(dNSName)
        expect(String(legacy)).toBe('example.com')
    })

    test('otherName is [0] { type-id, [0] EXPLICIT value }', () => {
        const name = new otherName({
            typeID: '1.3.6.1.4.1.311.20.2.3',
            value: new asn1js.Utf8String({ value: 'user@example.com' }),
        })
        const der = toHex(name.toDer())
        // A0 len 06 0A <oid> A0 12 0C 10 <utf8>
        expect(der.startsWith('a0')).toBe(true)
        expect(der).toContain('a0120c10')
        const parsed = parse(der) as otherName
        expect(parsed).toBeInstanceOf(otherName)
        expect(parsed.typeID.value).toBe('1.3.6.1.4.1.311.20.2.3')
        expect(toHex(parsed.toDer())).toBe(der)
    })

    test('ediPartyName tags nameAssigner [0] and partyName [1] and round-trips', () => {
        const name = new ediPartyName({
            nameAssigner: 'assigner',
            partyName: 'party',
        })
        const der = name.toDer()
        const parsed = GeneralName.fromAsn1(derToAsn1(der)) as ediPartyName
        expect(parsed).toBeInstanceOf(ediPartyName)
        expect(toHex(parsed.toDer())).toBe(toHex(der))
        expect(der[0]).toBe(0xa5) // [5] constructed, IMPLICIT
    })
})

describe('iPAddress.fromString', () => {
    const hex = (ip: string) =>
        Array.from(GeneralName.iPAddress.fromString(ip).bytes, (b) =>
            b.toString(16).padStart(2, '0'),
        ).join('')

    test('IPv4', () => {
        expect(hex('192.0.2.1')).toBe('c0000201')
        expect(hex('0.0.0.0')).toBe('00000000')
    })

    test('IPv6, compressed, bracketed and with an IPv4 tail', () => {
        expect(hex('2001:db8::1')).toBe('20010db8000000000000000000000001')
        expect(hex('[::1]')).toBe('00000000000000000000000000000001')
        expect(hex('::ffff:192.0.2.1')).toBe('00000000000000000000ffffc0000201')
        expect(hex('2001:DB8:0:0:0:0:0:1')).toBe(
            '20010db8000000000000000000000001',
        )
    })

    test('rejects what is not an IP address', () => {
        for (const text of [
            'example.com',
            '192.0.2',
            '192.0.2.256',
            '192.0.02.1', // leading zero: octal in some parsers
            '1::2::3',
            '1:2:3:4:5:6:7:8:9',
            '1:2:3:4:5:6:7:8::',
            'g::1',
        ]) {
            expect(() => GeneralName.iPAddress.fromString(text), text).toThrow()
        }
    })
})
