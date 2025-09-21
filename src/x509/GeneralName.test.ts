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

describe('AnotherName', () => {
    test('should create AnotherName with string typeID', () => {
        const anotherName = new AnotherName({
            typeID: '1.2.3.4.5',
            value: new UTF8String({ value: 'test value' }),
        })

        expect(anotherName.typeID).toBeInstanceOf(ObjectIdentifier)
        expect(anotherName.typeID.value).toBe('1.2.3.4.5')
        expect(anotherName.value).toBeDefined()
    })

    test('should create AnotherName with ObjectIdentifier typeID', () => {
        const oid = new ObjectIdentifier({ value: '1.2.3.4.5' })
        const anotherName = new AnotherName({
            typeID: oid,
            value: new UTF8String({ value: 'test value' }),
        })

        expect(anotherName.typeID.value).toBe(oid.value)
    })

    test('should convert to ASN.1 structure', () => {
        const anotherName = new AnotherName({
            typeID: '1.2.3.4.5',
            value: new UTF8String({ value: 'test' }),
        })

        const asn1 = anotherName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)
    })

    test('should parse from ASN.1 structure', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: '1.2.3.4.5' }),
                new asn1js.Utf8String({ value: 'test value' }),
            ],
        })

        const anotherName = AnotherName.fromAsn1(asn1)
        expect(anotherName.typeID.value).toBe('1.2.3.4.5')
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
        expect(directoryString.toString()).toBe('Test String')
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
        expect(ediPartyName.partyName.toString()).toBe('Test Party')
        expect(ediPartyName.nameAssigner).toBeUndefined()
    })

    test('should create EDIPartyName with nameAssigner', () => {
        const ediPartyName = new EDIPartyName({
            nameAssigner: 'Test Assigner',
            partyName: 'Test Party',
        })

        expect(ediPartyName.nameAssigner).toBeInstanceOf(UTF8String)
        expect(ediPartyName.nameAssigner!.toString()).toBe('Test Assigner')
        expect(ediPartyName.partyName.toString()).toBe('Test Party')
    })

    test('should convert to ASN.1 structure', () => {
        const ediPartyName = new EDIPartyName({
            nameAssigner: 'Assigner',
            partyName: 'Party',
        })

        const asn1 = ediPartyName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2) // nameAssigner + partyName
    })
})

describe('GeneralName types', () => {
    test('dNSName should work correctly', () => {
        const dnsName = new dNSName({ value: 'example.com' })

        expect(dnsName.toString()).toBe('example.com')

        const asn1 = dnsName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(2) // [2]
    })

    test('rfc822Name should work correctly', () => {
        const emailName = new rfc822Name({ value: 'test@example.com' })

        expect(emailName.toString()).toBe('test@example.com')

        const asn1 = emailName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(1) // [1]
    })

    test('uniformResourceIdentifier should work correctly', () => {
        const uri = new uniformResourceIdentifier({
            value: 'https://example.com',
        })

        expect(uri.toString()).toBe('https://example.com')

        const asn1 = uri.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(6) // [6]
    })

    test('iPAddress should work correctly', () => {
        // IPv4 address: 192.168.1.1
        const ipBytes = new Uint8Array([192, 168, 1, 1])
        const ipAddress = new iPAddress({ bytes: ipBytes })

        expect(ipAddress.bytes).toEqual(ipBytes)

        const asn1 = ipAddress.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(7) // [7]
    })

    test('registeredID should work correctly', () => {
        const regId = new registeredID({ value: '1.2.3.4.5.6' })

        expect(regId.value).toBe('1.2.3.4.5.6')

        const asn1 = regId.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(8) // [8]
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

        expect(dirName.length).toBe(1)

        const asn1 = dirName.toAsn1()
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(4) // [4]
    })
})

describe('GeneralName Choice', () => {
    test('should convert GeneralName to ASN.1', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const asn1 = GeneralName.toAsn1(dnsName)

        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagNumber).toBe(2) // dNSName tag
    })

    test('should parse GeneralName from ASN.1 dNSName', () => {
        const asn1 = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
            value: [new asn1js.IA5String({ value: 'example.com' })],
        })

        const generalName = GeneralName.fromAsn1(asn1)
        expect(generalName).toBeInstanceOf(dNSName)
        expect(generalName.toString()).toBe('example.com')
    })

    test('should parse GeneralName from ASN.1 rfc822Name', () => {
        const asn1 = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 }, // [1] rfc822Name
            value: [new asn1js.IA5String({ value: 'test@example.com' })],
        })

        const generalName = GeneralName.fromAsn1(asn1)
        expect(generalName).toBeInstanceOf(rfc822Name)
        expect(generalName.toString()).toBe('test@example.com')
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

        expect(generalNames.length).toBe(0)
    })

    test('should create GeneralNames with multiple names', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const emailName = new rfc822Name({ value: 'test@example.com' })

        const generalNames = new GeneralNames(dnsName, emailName)

        expect(generalNames.length).toBe(2)
        expect(generalNames[0]).toBe(dnsName)
        expect(generalNames[1]).toBe(emailName)
    })

    test('should convert to ASN.1 sequence', () => {
        const dnsName = new dNSName({ value: 'example.com' })
        const emailName = new rfc822Name({ value: 'test@example.com' })
        const generalNames = new GeneralNames(dnsName, emailName)

        const asn1 = generalNames.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(2)
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
        expect(generalNames.length).toBe(2)
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
