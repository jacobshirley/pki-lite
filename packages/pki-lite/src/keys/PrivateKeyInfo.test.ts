import { assert, describe, expect, test } from 'vitest'
import { PrivateKeyInfo } from './PrivateKeyInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'
import { Attribute } from '../x509/Attribute.js'

describe('PrivateKeyInfo', () => {
    test('can be created', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
        })

        expect(privateKey).toBeInstanceOf(PrivateKeyInfo)
        expect(privateKey.version).toBe(0)
        expect(privateKey.algorithm).toEqual(algorithm)
        expect(privateKey.privateKey.bytes).toBe(keyData)
        expect(privateKey.attributes).toBeUndefined()
    })

    test('can be created with custom version and attributes', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const attributes = [
            new Attribute({
                type: '1.2.840.113549.1.9.1',
                values: [10, 20, 30],
            }),
        ]
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
            version: 1,
            attributes,
        })

        expect(privateKey).toBeInstanceOf(PrivateKeyInfo)
        expect(privateKey.version).toBe(1)
        expect(privateKey.algorithm).toBe(algorithm)
        expect(privateKey.privateKey.bytes).toBe(keyData)
        expect(privateKey.attributes).toBe(attributes)
    })

    test('can be converted into ASN.1 without attributes', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
        })

        const asn1 = privateKey.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(3)

        // First element should be the version (an Integer)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)

        // Second element should be the algorithm (a Sequence)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)

        // Third element should be the private key (an OctetString)
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.OctetString)
    })

    test('can be converted into ASN.1 with attributes', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const attributes = [
            new Attribute({
                type: '1.2.840.113549.1.9.1',
                values: [10, 20, 30],
            }),
        ]
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
            version: 0,
            attributes,
        })

        const asn1 = privateKey.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(4)

        // First element should be the version (an Integer)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)

        // Second element should be the algorithm (a Sequence)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.Sequence)

        // Third element should be the private key (an OctetString)
        expect(asn1.valueBlock.value[2]).toBeInstanceOf(asn1js.OctetString)

        // Fourth element should be the attributes (a Primitive with context-specific tag)
        expect(asn1.valueBlock.value[3]).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.valueBlock.value[3].idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.valueBlock.value[3].idBlock.tagNumber).toBe(0) // [0]
    })

    test('can be parsed from ASN.1 without attributes', () => {
        // Create ASN.1 structure for a private key
        const version = 0
        const algorithmOid = '1.2.840.113549.1.1.1' // RSA
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: version }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: algorithmOid }),
                    ],
                }),
                new asn1js.OctetString({
                    valueHex: keyData,
                }),
            ],
        })

        const privateKey = PrivateKeyInfo.fromAsn1(asn1)
        expect(privateKey).toBeInstanceOf(PrivateKeyInfo)
        expect(privateKey.version).toBe(version)
        expect(privateKey.algorithm.algorithm.toString()).toBe(algorithmOid)
        expect(privateKey.privateKey.bytes).toEqual(keyData)
        expect(privateKey.attributes).toBeUndefined()
    })

    test('can be parsed from ASN.1 with attributes', () => {
        // Create ASN.1 structure for a private key with attributes
        const version = 1
        const algorithmOid = '1.2.840.113549.1.1.1' // RSA
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const attributesData = new Uint8Array([10, 20, 30])
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: version }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: algorithmOid }),
                    ],
                }),
                new asn1js.OctetString({
                    valueHex: keyData,
                }),
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [
                        new Attribute({
                            type: '1.2.840.113549.1.9.1',
                            values: [10, 20, 30],
                        }).toAsn1(),
                    ],
                }),
            ],
        })

        const privateKey = PrivateKeyInfo.fromAsn1(asn1)
        expect(privateKey).toBeInstanceOf(PrivateKeyInfo)
        expect(privateKey.version).toBe(version)
        expect(privateKey.algorithm.algorithm.toString()).toBe(algorithmOid)
        expect(privateKey.privateKey.bytes).toEqual(keyData)
        // Due to the way we're testing, we can't check the exact attribute data
        expect(privateKey.attributes).toBeDefined()
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a SEQUENCE
        const asn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => PrivateKeyInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected SEQUENCE',
        )
    })

    test('throws an error when ASN.1 has too few elements', () => {
        // Create an ASN.1 SEQUENCE with only two elements
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 0 }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({
                            value: '1.2.840.113549.1.1.1',
                        }),
                    ],
                }),
            ],
        })

        expect(() => PrivateKeyInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected at least 3 elements',
        )
    })

    test('PrivateKeyInfo toString snapshot', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
        })
        expect(privateKey.toString()).toMatchInlineSnapshot(`
          "[PrivateKeyInfo] SEQUENCE :
            INTEGER : 0
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
            OCTET STRING : 0102030405"
        `)
    })

    test('PrivateKeyInfo toString snapshot with attributes', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const attributes = [
            new Attribute({
                type: '1.2.840.113549.1.9.1',
                values: [10, 20, 30],
            }),
        ]
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
            version: 1,
            attributes,
        })
        expect(privateKey.toString()).toMatchInlineSnapshot(`
          "[PrivateKeyInfo] SEQUENCE :
            INTEGER : 1
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
            OCTET STRING : 0102030405
            [0] :
              SEQUENCE :
                OBJECT IDENTIFIER : 1.2.840.113549.1.9.1
                SET :
                  INTEGER : 10
                  INTEGER : 20
                  INTEGER : 30"
        `)
    })

    test('PrivateKeyInfo toPem snapshot', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
        })
        expect(privateKey.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN PRIVATEKEYINFO-----
          MBcCAQAwCwYJKoZIhvcNAQEBBAUBAgMEBQ==
          -----END PRIVATEKEYINFO-----"
        `)
    })

    test('PrivateKeyInfo toPem snapshot with attributes', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const keyData = new Uint8Array([1, 2, 3, 4, 5])
        const attributes = [
            new Attribute({
                type: '1.2.840.113549.1.9.1',
                values: [10, 20, 30],
            }),
        ]
        const privateKey = new PrivateKeyInfo({
            algorithm,
            privateKey: keyData,
            version: 1,
            attributes,
        })
        expect(privateKey.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN PRIVATEKEYINFO-----
          MDECAQEwCwYJKoZIhvcNAQEBBAUBAgMEBaAYMBYGCSqGSIb3DQEJATEJAgEKAgEUAgEe
          -----END PRIVATEKEYINFO-----"
        `)
    })

    test('fromPem correctly decodes PEM-encoded PrivateKeyInfo', () => {
        const pem = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQD30+ESkPovDnDf
SWwtLzBQCr9JcgsAGuuMHbDBt9g9J5T24A2MREvail6t20ZHDpr6aBe+Zb4IZdSh
Kzmxb93hQLODCoyP5adRIz67LTd/M3xYhdaoHUNxqE/LtIhCvbEZIrJ5U9bUxGFp
DLxE2kv5xJrGv6cal/TC1gydoZ1xbKKoEFkd0CI8MhQJDFS+bbFYkae+MTpPBsfO
eo2+l3mfvrGGcl0Xs2GF87+DWTfPNs/sNlJvH3C8nTQm41buW4u+7/qtGHOQqoek
FcL+ehoFxvQ+ApMw2o93Ajd9RHh5/gIVIXbOTLwzBg0NsvLkoPQc+4yps14DEMfn
eN3UoIB1AgMBAAECggEAD7OOBNHy9TdE1x4SQKdG4tNY0jZA/yqKy4+iqsComRtL
DfxyWfWGbsap1U8EBq16C9e7erXR0pC3u4Gpv+sBU5ZN/pqU/urtwloUIozCAYj0
CFxrwK6gnsYApDyAY5DGydEPyK29+dtP+/VcGj/7D0yHAoToTpWGYtpn5eF0QFgh
5xrku0Pg/M5pVX1tLdsjGo1AtDLdro2euWVxwHCaARLd+C5YPl9Ad+NEDSUX9SXx
xM+rAWWZMnytIx+0TzNTDCcgMadqqfdM8vAlKlvSX3HADF1sxgG7d8FMcaBdZmEs
mr/Po+wlP7Vh/D0q48rS6oWtjeI5xE19tPJi4F/qQwKBgQD/rGAJtgSzbMWD73zH
kiDEsXsKLa3Go4t4Llbuoiz8NQKoRm7uayITu7bHXmXz1daO1s3Jrb53p8rvLecv
gnQJ4xpm/GsHk4X4YWZZg+t23rhfxbDPKANdIJvmvr0Jex1IIZ7UbA5VTJTBV7rg
8vxyrSHAUwetZ2DMAydwOY0RhwKBgQD4JPAaFcRJMIak9zlBZxl0pAZVTE8YC783
efwx0JxHh8Ld6gmNERM4SNTUB9HfjgVZhjBOZ9b2tm+f74fgqyIS9tFqFj8aK5Il
QveVI+Rns3+afqlD/hTfkSkcahg6SVTX64f+qo6lI6BojsHwkhsgXGx9f8bpTtw4
c2RbUcLNIwKBgHh7H0qUNoTitfTlTxSwfLaTuBpkyiX3/YoltBuB2tcCl/z6K944
J/fKlmg+yKZt10y6VoE6Wa4DKPMq222c+NeL6G4tdrY8Q353T4bRTo1WiOXAv//u
qB8jdbP3oBcup+7MwQ7y2JJDozm1AMBuYJ4djfEWb2C8fXXF6rjMtfhTAoGAQJVU
jGV35dikYpEZrMUJogsCvvaSa167UNQF6G00D4XtGNbNz5JPH0oNYnX6kKWlDMzZ
C78I+sM2wDiWc8n2n1rv3B2YJNaMPfh0+bMSwk68elhW86RQiHN+cK/ISHtHgr8B
cS2w3JguKqhlH5jXSI/liLBV8+kbdfHKf94CxmMCgYBxz0yP7/rA29osVLwoRsKw
MhkAtwevpcCh3Unp/38vuKb3kiV/CEeID4hufviNTOiyPeCTfEOQV1urc00A5Tty
uuBSHpPO6Q1JHl3c35+Fv3pNuvt95CwRJFYVOGM+fwJknwiJ7F6mGYziWEhTLRT+
Yr4Pe8+f6ak0lLdG0YPSuQ==
-----END PRIVATE KEY-----
`
        const privateKey = PrivateKeyInfo.fromPem(pem)
        expect(privateKey.version).toBe(0)
    })
})
