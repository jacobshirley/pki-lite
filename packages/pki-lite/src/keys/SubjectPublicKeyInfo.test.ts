import { assert, describe, expect, test } from 'vitest'
import { SubjectPublicKeyInfo } from './SubjectPublicKeyInfo.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../core/PkiBase.js'

describe('SubjectPublicKeyInfo', () => {
    test('can be created', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])

        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })

        expect(spki).toBeInstanceOf(SubjectPublicKeyInfo)
        expect(spki.algorithm).toEqual(algorithm)
        expect(spki.subjectPublicKey.bytes).toEqual(publicKey)
    })

    test('can be created with algorithm parameters', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.10045.2.1',
            parameters: new Uint8Array([6, 7, 8]),
        }) // EC with params
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])

        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })

        expect(spki).toBeInstanceOf(SubjectPublicKeyInfo)
        expect(spki.algorithm).toEqual(algorithm)
        expect(spki.subjectPublicKey.bytes).toEqual(publicKey)
    })

    test('can be converted to ASN.1', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])

        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })
        const asn1 = spki.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2) // algorithm, subjectPublicKey

        const [algorithmBlock, keyBlock] = asn1.valueBlock.value

        expect(algorithmBlock).toBeInstanceOf(asn1js.Sequence)
        expect(keyBlock).toBeInstanceOf(asn1js.BitString)
        expect((keyBlock as asn1js.BitString).valueBlock.valueHexView).toEqual(
            publicKey,
        )
    })

    test('can be parsed from ASN.1', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const publicKey = new Uint8Array([1, 2, 3, 4, 5])

        // Create ASN.1 structure manually
        const asn1 = new asn1js.Sequence({
            value: [
                algorithm.toAsn1(),
                new asn1js.BitString({ valueHex: publicKey }),
            ],
        })

        const spki = SubjectPublicKeyInfo.fromAsn1(asn1)
        expect(spki).toBeInstanceOf(SubjectPublicKeyInfo)
        expect(spki.algorithm.algorithm).toEqual(algorithm.algorithm)
        expect(spki.subjectPublicKey.bytes).toEqual(publicKey)
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a sequence
        const asn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => SubjectPublicKeyInfo.fromAsn1(asn1)).toThrow(
            'Expected Sequence',
        )
    })

    test('throws an error when subjectPublicKey is not a BitString', () => {
        // Create an ASN.1 sequence with invalid subjectPublicKey field
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        }) // RSA
        const asn1 = new asn1js.Sequence({
            value: [
                algorithm.toAsn1(),
                new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]) }),
            ],
        })

        expect(() => SubjectPublicKeyInfo.fromAsn1(asn1)).toThrow(
            'Expected BitString for subjectPublicKey',
        )
    })

    test('toString snapshot', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const publicKey = new Uint8Array([
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        ])
        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })
        expect(spki.toString()).toMatchInlineSnapshot(`
          "[SubjectPublicKeyInfo] SEQUENCE :
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.1.1
            BIT STRING : 0011000010000010000000010000101000000010100000100000000100000001"
        `)
    })

    test('toPem snapshot', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const publicKey = new Uint8Array([
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        ])
        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })
        expect(spki.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN SUBJECTPUBLICKEYINFO-----
          MBgwCwYJKoZIhvcNAQEBAwkAMIIBCgKCAQE=
          -----END SUBJECTPUBLICKEYINFO-----"
        `)
    })

    test('toString snapshot for ECDSA', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.10045.2.1',
        })
        const publicKey = new Uint8Array([0x04, 0x41, 0x04])
        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })
        expect(spki.toString()).toMatchInlineSnapshot(`
          "[SubjectPublicKeyInfo] SEQUENCE :
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.10045.2.1
            BIT STRING : 000001000100000100000100"
        `)
    })

    test('toPem snapshot for ECDSA', () => {
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.10045.2.1',
        })
        const publicKey = new Uint8Array([0x04, 0x41, 0x04])
        const spki = new SubjectPublicKeyInfo({
            algorithm,
            subjectPublicKey: publicKey,
        })
        expect(spki.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN SUBJECTPUBLICKEYINFO-----
          MBEwCQYHKoZIzj0CAQMEAARBBA==
          -----END SUBJECTPUBLICKEYINFO-----"
        `)
    })
})
