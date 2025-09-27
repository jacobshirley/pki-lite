import { describe, test, expect } from 'vitest'
import { IssuerSerial } from './IssuerSerial.js'
import { Name } from './Name.js'
import { GeneralNames, GeneralName } from './GeneralName.js'
import { Integer } from '../asn1/Integer.js'
import { asn1js } from '../core/PkiBase.js'

describe('IssuerSerial', () => {
    test('constructs from GeneralNames', () => {
        const gn = new GeneralNames(
            GeneralName.directoryName.fromName(new Name.RDNSequence()),
        )
        const serial = new Integer({ value: 12345 })
        const iser = new IssuerSerial({ issuer: gn, serialNumber: serial })
        expect(iser.issuer).toBe(gn)
        expect(iser.serialNumber.toNumber()).toBe(12345)
    })

    test('constructs from Name', () => {
        const name = new Name.RDNSequence()
        const serial = new Integer({ value: 67890 })
        const iser = new IssuerSerial({ issuer: name, serialNumber: serial })
        expect(iser.issuer).toBeInstanceOf(GeneralNames)
        expect(iser.serialNumber.toNumber()).toBe(67890)
    })

    test('ASN.1 encode/decode roundtrip', () => {
        const name = new Name.RDNSequence()
        const serial = new Integer({ value: 42 })
        const iser = new IssuerSerial({ issuer: name, serialNumber: serial })
        const asn1 = iser.toAsn1()
        const decoded = IssuerSerial.fromAsn1(asn1)
        expect(decoded.issuer.toDer().toString()).toBe(
            iser.issuer.toDer().toString(),
        )
        expect(decoded.serialNumber.toNumber()).toBe(42)
    })

    test('throws on invalid ASN.1 (not sequence)', () => {
        expect(() =>
            IssuerSerial.fromAsn1(new asn1js.Integer({ value: 1 })),
        ).toThrow('expected SEQUENCE')
    })

    test('throws on invalid ASN.1 (wrong element count)', () => {
        const seq = new asn1js.Sequence({
            value: [new asn1js.Integer({ value: 1 })],
        })
        expect(() => IssuerSerial.fromAsn1(seq)).toThrow('expected 2 elements')
    })
})
