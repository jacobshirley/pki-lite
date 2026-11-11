import { assert, describe, expect, test } from 'vitest'
import { AuthorityKeyIdentifier } from './AuthorityKeyIdentifier.js'
import { KeyIdentifier } from '../../pkcs7/recipients/KeyIdentifier.js'
import { GeneralNames, dNSName } from '../GeneralName.js'
import { Integer } from '../../asn1/Integer.js'
import * as asn1js from 'asn1js'
import { Extension } from '../Extension.js'
import { derToAsn1 } from '../../core/PkiBase.js'

describe('AuthorityKeyIdentifier', () => {
    test('should create AuthorityKeyIdentifier with only keyIdentifier', () => {
        const keyId = new KeyIdentifier({
            bytes: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const aki = new AuthorityKeyIdentifier({
            keyIdentifier: keyId,
        })

        expect(aki.keyIdentifier).toEqual(keyId)
        expect(aki.authorityCertIssuer).toBeUndefined()
        expect(aki.authorityCertSerialNumber).toBeUndefined()
    })

    test('should create AuthorityKeyIdentifier with all fields', () => {
        const keyId = new KeyIdentifier({
            bytes: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const generalNames = new GeneralNames(
            new dNSName({ value: 'ca.example.com' }),
        )
        const serialNumber = 12345n

        const aki = new AuthorityKeyIdentifier({
            keyIdentifier: keyId,
            authorityCertIssuer: generalNames,
            authorityCertSerialNumber: serialNumber,
        })

        expect(aki.keyIdentifier).toEqual(keyId)
        expect(aki.authorityCertIssuer).toEqual(generalNames)
        expect(aki.authorityCertSerialNumber).toBeInstanceOf(Integer)
        expect(aki.authorityCertSerialNumber!.toBigInt()).toEqual(serialNumber)
    })

    test('should create AuthorityKeyIdentifier with number serial number', () => {
        const aki = new AuthorityKeyIdentifier({
            authorityCertSerialNumber: 123,
        })

        expect(aki.authorityCertSerialNumber).toBeInstanceOf(Integer)
        expect(aki.authorityCertSerialNumber!.toInteger()).toEqual(123)
    })

    test('should create AuthorityKeyIdentifier with Uint8Array<ArrayBuffer> serial number', () => {
        const serialBytes = new Uint8Array([0x01, 0x02, 0x03])
        const aki = new AuthorityKeyIdentifier({
            authorityCertSerialNumber: serialBytes,
        })

        expect(aki.authorityCertSerialNumber).toBeInstanceOf(Integer)
        expect(aki.authorityCertSerialNumber!.bytes).toEqual(serialBytes)
    })

    test('should create AuthorityKeyIdentifier with Integer serial number', () => {
        const integer = new Integer({ value: 456n })
        const aki = new AuthorityKeyIdentifier({
            authorityCertSerialNumber: integer,
        })

        expect(aki.authorityCertSerialNumber!.toBigInt()).toEqual(456n)
    })

    test('should convert to ASN.1 with only keyIdentifier', () => {
        const keyId = new KeyIdentifier({
            bytes: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const aki = new AuthorityKeyIdentifier({
            keyIdentifier: keyId,
        })

        const asn1 = aki.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(1)

        const keyIdBlock = asn1.valueBlock.value[0] as asn1js.Constructed
        expect(keyIdBlock.idBlock.tagClass).toEqual(3) // CONTEXT-SPECIFIC
        expect(keyIdBlock.idBlock.tagNumber).toEqual(0) // [0]
    })

    test('should convert to ASN.1 with all fields', () => {
        const keyId = new KeyIdentifier({
            bytes: new Uint8Array([1, 2, 3, 4, 5]),
        })
        const generalNames = new GeneralNames(
            new dNSName({ value: 'ca.example.com' }),
        )
        const aki = new AuthorityKeyIdentifier({
            keyIdentifier: keyId,
            authorityCertIssuer: generalNames,
            authorityCertSerialNumber: 123n,
        })

        const asn1 = aki.toAsn1()
        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(3)

        const keyIdBlock = asn1.valueBlock.value[0] as asn1js.Constructed
        expect(keyIdBlock.idBlock.tagNumber).toEqual(0)

        const issuerBlock = asn1.valueBlock.value[1] as asn1js.Constructed
        expect(issuerBlock.idBlock.tagNumber).toEqual(1)

        const serialBlock = asn1.valueBlock.value[2] as asn1js.Constructed
        expect(serialBlock.idBlock.tagNumber).toEqual(2)
    })

    test('should parse from ASN.1 with keyIdentifier', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 }, // [0]
                    value: [
                        new asn1js.OctetString({
                            valueHex: new Uint8Array([1, 2, 3, 4, 5]),
                        }),
                    ],
                }),
            ],
        })

        const aki = AuthorityKeyIdentifier.fromAsn1(asn1)
        expect(aki.keyIdentifier).toBeInstanceOf(KeyIdentifier)
        expect(aki.keyIdentifier!.bytes).toEqual(
            new Uint8Array([1, 2, 3, 4, 5]),
        )
        expect(aki.authorityCertIssuer).toBeUndefined()
        expect(aki.authorityCertSerialNumber).toBeUndefined()
    })

    test('should parse from ASN.1 with all fields', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 }, // [0] keyIdentifier
                    value: [
                        new KeyIdentifier({
                            bytes: new Uint8Array([1, 2, 3, 4, 5]),
                        }).toAsn1(),
                    ],
                }),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 1 }, // [1] authorityCertIssuer
                    value: [
                        new asn1js.Sequence({
                            value: [
                                new asn1js.Constructed({
                                    idBlock: { tagClass: 3, tagNumber: 2 }, // [2] dNSName
                                    value: [
                                        new asn1js.IA5String({
                                            value: 'ca.example.com',
                                        }),
                                    ],
                                }),
                            ],
                        }),
                    ],
                }),
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 2 }, // [2] authorityCertSerialNumber
                    value: [new asn1js.Integer({ value: 123 })],
                }),
            ],
        })

        const aki = AuthorityKeyIdentifier.fromAsn1(asn1)
        expect(aki.keyIdentifier).toBeInstanceOf(KeyIdentifier)
        expect(aki.authorityCertIssuer).toBeInstanceOf(GeneralNames)
        expect(aki.authorityCertSerialNumber).toBeInstanceOf(Integer)
        expect(aki.authorityCertSerialNumber!.toInteger()).toEqual(123)
    })

    test('fromAsn1 should accept an empty sequence (all fields optional)', () => {
        const asn1 = new asn1js.Sequence({ value: [] })

        const aki = AuthorityKeyIdentifier.fromAsn1(asn1)
        expect(aki.keyIdentifier).toBeUndefined()
        expect(aki.authorityCertIssuer).toBeUndefined()
        expect(aki.authorityCertSerialNumber).toBeUndefined()
        expect(
            Array.from(aki.toDer(), (b) =>
                b.toString(16).padStart(2, '0'),
            ).join(''),
        ).toBe('3000')
    })

    test('should handle round-trip conversion through ASN.1', () => {
        const testCases = [
            {
                keyIdentifier: new KeyIdentifier({
                    bytes: new Uint8Array([1, 2, 3, 4, 5]),
                }),
            },
            {
                authorityCertSerialNumber: 12345n,
            },
            {
                keyIdentifier: new KeyIdentifier({
                    bytes: new Uint8Array([6, 7, 8, 9, 10]),
                }),
                authorityCertIssuer: new GeneralNames(
                    new dNSName({ value: 'ca.example.com' }),
                ),
                authorityCertSerialNumber: 98765n,
            },
        ]

        for (const testCase of testCases) {
            const original = new AuthorityKeyIdentifier(testCase)
            const asn1 = original.toAsn1()
            const decoded = AuthorityKeyIdentifier.fromAsn1(asn1)

            if (testCase.keyIdentifier) {
                expect(decoded.keyIdentifier).toBeInstanceOf(KeyIdentifier)
                expect(decoded.keyIdentifier!.bytes).toEqual(
                    testCase.keyIdentifier.bytes,
                )
            }
            if (testCase.authorityCertIssuer) {
                expect(decoded.authorityCertIssuer).toBeInstanceOf(GeneralNames)
                expect(decoded.authorityCertIssuer!.length).toEqual(
                    testCase.authorityCertIssuer.length,
                )
            }
            if (testCase.authorityCertSerialNumber) {
                expect(decoded.authorityCertSerialNumber).toBeInstanceOf(
                    Integer,
                )
                expect(decoded.authorityCertSerialNumber!.toBigInt()).toEqual(
                    testCase.authorityCertSerialNumber,
                )
            }
        }
    })

    test('should handle typical CA certificate scenarios', () => {
        // Root CA - might not have AKI or just keyIdentifier
        const rootCA_AKI = new AuthorityKeyIdentifier({
            keyIdentifier: new KeyIdentifier({
                bytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            }),
        })
        expect(rootCA_AKI.keyIdentifier).toBeDefined()
        expect(rootCA_AKI.authorityCertIssuer).toBeUndefined()

        // Intermediate CA - full AKI with all fields
        const intermediate_AKI = new AuthorityKeyIdentifier({
            keyIdentifier: new KeyIdentifier({
                bytes: new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55]),
            }),
            authorityCertIssuer: new GeneralNames(
                new dNSName({ value: 'root-ca.example.com' }),
            ),
            authorityCertSerialNumber: 0x123456789abcdefn,
        })
        expect(intermediate_AKI.keyIdentifier).toBeDefined()
        expect(intermediate_AKI.authorityCertIssuer).toBeDefined()
        expect(intermediate_AKI.authorityCertSerialNumber).toBeDefined()
    })

    describe('encoding (RFC 5280, IMPLICIT TAGS)', () => {
        const toHex = (b: Uint8Array) =>
            Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
        const fromHex = (hex: string) =>
            new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)))

        test('keyIdentifier is a primitive [0], not an explicit wrapper', () => {
            const aki = new AuthorityKeyIdentifier({
                keyIdentifier: new KeyIdentifier({
                    bytes: new Uint8Array([1, 2, 3, 4]),
                }),
            })
            // SEQUENCE { [0] 01020304 }
            expect(toHex(aki.toDer())).toBe('30068004' + '01020304')
        })

        test('authorityCertIssuer holds the GeneralNames directly; serial is a primitive [2]', () => {
            const aki = new AuthorityKeyIdentifier({
                authorityCertIssuer: new GeneralNames(
                    new dNSName({ value: 'ca.example' }),
                ),
                authorityCertSerialNumber: 5,
            })
            // SEQUENCE { [1] { [2] "ca.example" }, [2] 05 }
            expect(toHex(aki.toDer())).toBe(
                '3011' + 'a10c820a63612e6578616d706c65' + '820105',
            )
        })

        test('parses the DER OpenSSL writes and re-encodes it identically', () => {
            const hex =
                '3017' +
                '8004deadbeef' +
                'a10c820a63612e6578616d706c65' +
                '820105'
            const parsed = AuthorityKeyIdentifier.fromAsn1(
                derToAsn1(fromHex(hex)),
            )
            expect(toHex(parsed.keyIdentifier!.bytes)).toBe('deadbeef')
            expect(parsed.authorityCertIssuer!.length).toBe(1)
            expect(parsed.authorityCertSerialNumber!.toInteger()).toBe(5)
            expect(toHex(parsed.toDer())).toBe(hex)
        })

        test('still parses the explicit form written by earlier versions', () => {
            // SEQUENCE { [0] { OCTET STRING 01020304 } }
            const parsed = AuthorityKeyIdentifier.fromAsn1(
                derToAsn1(fromHex('3008a006' + '040401020304')),
            )
            expect(toHex(parsed.keyIdentifier!.bytes)).toBe('01020304')
        })
    })
})
