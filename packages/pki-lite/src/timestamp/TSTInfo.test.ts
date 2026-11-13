import { assert, describe, expect, test } from 'vitest'
import { TSTInfo, Accuracy } from './TSTInfo.js'
import { MessageImprint } from './MessageImprint.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Extension } from '../x509/Extension.js'
import { GeneralName } from '../x509/GeneralName.js'
import { asn1js } from '../core/PkiBase.js'
const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('Accuracy', () => {
    test('can be created with all fields', () => {
        const accuracy = new Accuracy({
            seconds: 1,
            millis: 500,
            micros: 250,
        })

        expect(accuracy.seconds).toEqual(1)
        expect(accuracy.millis).toEqual(500)
        expect(accuracy.micros).toEqual(250)
    })

    test('can be created with only seconds', () => {
        const accuracy = new Accuracy({ seconds: 5 })

        expect(accuracy.seconds).toEqual(5)
        expect(accuracy.millis).toBeUndefined()
        expect(accuracy.micros).toBeUndefined()
    })

    test('can be created with no fields', () => {
        const accuracy = new Accuracy({})

        expect(accuracy.seconds).toBeUndefined()
        expect(accuracy.millis).toBeUndefined()
        expect(accuracy.micros).toBeUndefined()
    })

    test('throws error for invalid millis range', () => {
        expect(() => new Accuracy({ millis: 0 })).toThrow(
            'millis must be between 1 and 999',
        )
        expect(() => new Accuracy({ millis: 1000 })).toThrow(
            'millis must be between 1 and 999',
        )
    })

    test('throws error for invalid micros range', () => {
        expect(() => new Accuracy({ micros: 0 })).toThrow(
            'micros must be between 1 and 999',
        )
        expect(() => new Accuracy({ micros: 1000 })).toThrow(
            'micros must be between 1 and 999',
        )
    })

    test('can be converted to ASN.1', () => {
        const accuracy = new Accuracy({
            seconds: 1,
            millis: 500,
            micros: 250,
        })

        const asn1 = accuracy.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3)

        // Seconds
        assert(asn1.valueBlock.value[0] instanceof asn1js.Integer)
        expect(asn1.valueBlock.value[0].valueBlock.valueDec).toEqual(1)

        // Millis [0] and micros [1]: IMPLICIT (primitive), as in the RFC 3161 module
        expect(asn1.valueBlock.value[1].idBlock.tagClass).toEqual(3)
        expect(asn1.valueBlock.value[1].idBlock.tagNumber).toEqual(0)
        expect(asn1.valueBlock.value[1].idBlock.isConstructed).toBe(false)
        expect(asn1.valueBlock.value[2].idBlock.tagClass).toEqual(3)
        expect(asn1.valueBlock.value[2].idBlock.tagNumber).toEqual(1)
        expect(asn1.valueBlock.value[2].idBlock.isConstructed).toBe(false)
        expect(hex(accuracy.toDer())).toBe('300b020101800201f4810200fa')
    })

    test('reads the explicitly tagged form older versions wrote', () => {
        const explicit = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [new asn1js.Integer({ value: 500 })],
                }),
            ],
        })
        expect(Accuracy.fromAsn1(explicit).millis).toBe(500)
    })

    test('can be created from ASN.1', () => {
        const original = new Accuracy({
            seconds: 2,
            millis: 100,
            micros: 50,
        })

        const asn1 = original.toAsn1()
        const recreated = Accuracy.fromAsn1(asn1)

        expect(recreated.seconds).toEqual(2)
        expect(recreated.millis).toEqual(100)
        expect(recreated.micros).toEqual(50)
    })

    test('roundtrip conversion preserves data', () => {
        const original = new Accuracy({
            seconds: 3,
            millis: 999,
            micros: 1,
        })

        const asn1 = original.toAsn1()
        const recreated = Accuracy.fromAsn1(asn1)
        const asn1Again = recreated.toAsn1()

        expect(asn1.toBER(false)).toEqual(asn1Again.toBER(false))
    })
})

describe('TSTInfo', () => {
    const createTestMessageImprint = () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1', // SHA-256
        })
        const hashedMessage = new Uint8Array([1, 2, 3, 4, 5])
        return new MessageImprint({ hashAlgorithm, hashedMessage })
    }

    test('can be created with minimal parameters', () => {
        const messageImprint = createTestMessageImprint()
        const policy = '1.2.3.4.5'
        const serialNumber = new Uint8Array([1, 2, 3, 4])
        const genTime = new Date('2024-12-14T10:00:00Z')

        const tstInfo = new TSTInfo({
            policy,
            messageImprint,
            serialNumber,
            genTime,
        })

        expect(tstInfo.version).toEqual(1)
        expect(tstInfo.policy.toString()).toEqual(policy)
        expect(tstInfo.messageImprint).toEqual(messageImprint)
        expect(tstInfo.serialNumber).toEqual(serialNumber)
        expect(tstInfo.genTime).toEqual(genTime)
        expect(tstInfo.ordering).toEqual(false)
    })

    test('can be created with all parameters', () => {
        const messageImprint = createTestMessageImprint()
        const policy = '1.2.3.4.5'
        const serialNumber = new Uint8Array([1, 2, 3, 4])
        const genTime = new Date('2024-12-14T10:00:00Z')
        const accuracy = new Accuracy({ seconds: 1 })
        const nonce = new Uint8Array([5, 6, 7, 8])
        const tsa = new GeneralName.dNSName({ value: 'tsa.example.com' })
        const extensions = [
            new Extension({
                extnID: '1.2.3.4',
                critical: false,
                extnValue: 123,
            }),
        ]

        const tstInfo = new TSTInfo({
            version: 1,
            policy,
            messageImprint,
            serialNumber,
            genTime,
            accuracy,
            ordering: true,
            nonce,
            tsa,
            extensions,
        })

        expect(tstInfo.version).toEqual(1)
        expect(tstInfo.policy.toString()).toEqual(policy)
        expect(tstInfo.messageImprint).toEqual(messageImprint)
        expect(tstInfo.serialNumber).toEqual(serialNumber)
        expect(tstInfo.genTime).toEqual(genTime)
        expect(tstInfo.accuracy).toEqual(accuracy)
        expect(tstInfo.ordering).toEqual(true)
        expect(tstInfo.nonce).toEqual(nonce)
        expect(tstInfo.tsa).toEqual(tsa)
        expect(tstInfo.extensions).toEqual(extensions)
    })

    test('can be converted to ASN.1 with minimal parameters', () => {
        const messageImprint = createTestMessageImprint()
        const tstInfo = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
        })

        const asn1 = tstInfo.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(5)

        // Version
        assert(asn1.valueBlock.value[0] instanceof asn1js.Integer)
        expect(asn1.valueBlock.value[0].valueBlock.valueDec).toEqual(1)

        // Policy
        assert(asn1.valueBlock.value[1] instanceof asn1js.ObjectIdentifier)

        // MessageImprint
        assert(asn1.valueBlock.value[2] instanceof asn1js.Sequence)

        // SerialNumber
        assert(asn1.valueBlock.value[3] instanceof asn1js.Integer)

        // GenTime
        assert(asn1.valueBlock.value[4] instanceof asn1js.GeneralizedTime)
    })

    test('can be converted to ASN.1 with all parameters', () => {
        const messageImprint = createTestMessageImprint()
        const accuracy = new Accuracy({ seconds: 1, millis: 500 })
        const nonce = new Uint8Array([5, 6, 7, 8])
        const tsa = new GeneralName.dNSName({ value: 'tsa.example.com' })
        const extensions = [
            new Extension({
                extnID: '1.2.3.4',
                critical: false,
                extnValue: 123,
            }),
        ]

        const tstInfo = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
            accuracy,
            ordering: true,
            nonce,
            tsa,
            extensions,
        })

        const asn1 = tstInfo.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(10)

        // Version, Policy, MessageImprint, SerialNumber, GenTime
        // Accuracy, Ordering, Nonce, TSA, Extensions
    })

    test('can be created from ASN.1 with minimal parameters', () => {
        const messageImprint = createTestMessageImprint()
        const original = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
        })

        const asn1 = original.toAsn1()
        const recreated = TSTInfo.fromAsn1(asn1)

        expect(recreated.version).toEqual(1)
        expect(recreated.policy.toString()).toEqual('1.2.3.4.5')
        expect(
            recreated.messageImprint.hashAlgorithm.algorithm.toString(),
        ).toEqual(messageImprint.hashAlgorithm.algorithm.toString())
        expect(recreated.serialNumber).toEqual(original.serialNumber)
        expect(recreated.genTime.toISOString()).toEqual(
            original.genTime.toISOString(),
        )
        expect(recreated.ordering).toEqual(false)
    })

    test('can be created from ASN.1 with all parameters', () => {
        const messageImprint = createTestMessageImprint()
        const accuracy = new Accuracy({ seconds: 1, millis: 500 })
        const nonce = new Uint8Array([5, 6, 7, 8])
        const tsa = new GeneralName.dNSName({ value: 'tsa.example.com' })

        const original = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
            accuracy,
            ordering: true,
            nonce,
            tsa,
        })

        const asn1 = original.toAsn1()
        const recreated = TSTInfo.fromAsn1(asn1)

        expect(recreated.version).toEqual(1)
        expect(recreated.policy.toString()).toEqual('1.2.3.4.5')
        expect(recreated.serialNumber).toEqual(original.serialNumber)
        expect(recreated.accuracy?.seconds).toEqual(1)
        expect(recreated.accuracy?.millis).toEqual(500)
        expect(recreated.ordering).toEqual(true)
        expect(recreated.nonce).toEqual(nonce)
        expect(recreated.tsa?.toString()).toEqual('tsa.example.com')
    })

    test('roundtrip conversion preserves data', () => {
        const messageImprint = createTestMessageImprint()
        const accuracy = new Accuracy({ seconds: 1, millis: 500, micros: 250 })

        const original = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
            accuracy,
            ordering: true,
            nonce: crypto.getRandomValues(new Uint8Array(8)),
        })

        const asn1 = original.toAsn1()
        const recreated = TSTInfo.fromAsn1(asn1)
        const asn1Again = recreated.toAsn1()

        expect(original.toDer()).toEqual(recreated.toDer())
        expect(asn1.toBER(false)).toEqual(asn1Again.toBER(false))
    })

    test('fromAsn1 throws error for invalid structure', () => {
        const invalidAsn1 = new asn1js.Integer({ value: 1 })

        expect(() => TSTInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('fromAsn1 throws error for insufficient elements', () => {
        const invalidAsn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                new asn1js.ObjectIdentifier({ value: '1.2.3' }),
            ],
        })

        expect(() => TSTInfo.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure: expected at least 5 elements',
        )
    })

    test('fromAsn1 throws error for unsupported version', () => {
        const messageImprint = createTestMessageImprint()

        const invalidAsn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 2 }), // Version 2, unsupported
                new asn1js.ObjectIdentifier({ value: '1.2.3' }),
                messageImprint.toAsn1(),
                new asn1js.Integer({ value: 1 }),
                new asn1js.GeneralizedTime({ valueDate: new Date() }),
            ],
        })

        expect(() => TSTInfo.fromAsn1(invalidAsn1)).toThrow(
            'Unsupported TSTInfo version: 2',
        )
    })

    test('handles large serial numbers (up to 160 bits)', () => {
        const messageImprint = createTestMessageImprint()
        // 160 bits = 20 bytes
        const largeSerialNumber = new Uint8Array(20).map((_, i) => i + 1)

        const tstInfo = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: largeSerialNumber,
            genTime: new Date('2024-12-14T10:00:00Z'),
        })

        const asn1 = tstInfo.toAsn1()
        const recreated = TSTInfo.fromAsn1(asn1)

        expect(recreated.serialNumber).toEqual(largeSerialNumber)
    })

    test('ordering defaults to false', () => {
        const messageImprint = createTestMessageImprint()

        const tstInfo = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
        })

        expect(tstInfo.ordering).toEqual(false)

        // Should not be included in ASN.1 when false (DEFAULT)
        const asn1 = tstInfo.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        const hasBoolean = asn1.valueBlock.value.some(
            (v) => v instanceof asn1js.Boolean,
        )
        expect(hasBoolean).toEqual(false)
    })

    test('ordering is included when true', () => {
        const messageImprint = createTestMessageImprint()

        const tstInfo = new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint,
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
            ordering: true,
        })

        const asn1 = tstInfo.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)

        const hasBoolean = asn1.valueBlock.value.some(
            (v) => v instanceof asn1js.Boolean,
        )
        expect(hasBoolean).toEqual(true)
    })
})

describe('TSTInfo extensions: [1] IMPLICIT Extensions (RFC 3161)', () => {
    const createTestMessageImprint = () => {
        const hashAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.2.1', // SHA-256
        })
        const hashedMessage = new Uint8Array([1, 2, 3, 4, 5])
        return new MessageImprint({ hashAlgorithm, hashedMessage })
    }
    const extensions = [
        new Extension({ extnID: '1.2.3.4', extnValue: 123 }),
        new Extension({ extnID: '1.2.3.5', critical: true, extnValue: 456 }),
    ]
    const make = () =>
        new TSTInfo({
            policy: '1.2.3.4.5',
            messageImprint: createTestMessageImprint(),
            serialNumber: new Uint8Array([1, 2, 3, 4]),
            genTime: new Date('2024-12-14T10:00:00Z'),
            extensions,
        })
    const tagged = (value: asn1js.BaseBlock[]) =>
        new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value,
        })
    // The encoding of `make()` with its extensions field replaced, parsed from DER
    const withExtensionsField = (field: asn1js.BaseBlock) => {
        const asn1 = make().toAsn1() as asn1js.Sequence
        const values = asn1.valueBlock.value
        values[values.length - 1] = field
        return asn1js.fromBER(asn1.toBER(false)).result
    }

    test('writes the Extension elements directly inside [1]', () => {
        const values = (make().toAsn1() as asn1js.Sequence).valueBlock.value
        const field = values[values.length - 1]
        const expected = tagged(extensions.map((ext) => ext.toAsn1()))
        expect(hex(new Uint8Array(field.toBER(false)))).toBe(
            hex(new Uint8Array(expected.toBER(false))),
        )
    })

    test('parses the IMPLICIT form', () => {
        const parsed = TSTInfo.fromAsn1(
            withExtensionsField(tagged(extensions.map((ext) => ext.toAsn1()))),
        )
        expect(parsed.extensions?.map((ext) => ext.extnID.value)).toEqual([
            '1.2.3.4',
            '1.2.3.5',
        ])
        expect(parsed.extensions?.[1].critical).toBe(true)
    })

    test('still parses the explicitly tagged form written by earlier versions', () => {
        const legacy = tagged([
            new asn1js.Sequence({
                value: extensions.map((ext) => ext.toAsn1()),
            }),
        ])
        const parsed = TSTInfo.fromAsn1(withExtensionsField(legacy))
        expect(parsed.extensions?.map((ext) => ext.extnID.value)).toEqual([
            '1.2.3.4',
            '1.2.3.5',
        ])
    })
})
