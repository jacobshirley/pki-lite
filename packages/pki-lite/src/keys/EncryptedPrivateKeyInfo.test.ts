import { assert, describe, expect, test } from 'vitest'
import { EncryptedPrivateKeyInfo } from './EncryptedPrivateKeyInfo.js'
import { ContentEncryptionAlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { OctetString } from '../asn1/OctetString.js'
import { asn1js } from '../core/PkiBase.js'

describe('EncryptedPrivateKeyInfo', () => {
    test('can be created with OctetString', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13', // PBES2
        })
        const encryptedData = new OctetString({
            bytes: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        })

        const epki = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        expect(epki).toBeInstanceOf(EncryptedPrivateKeyInfo)
        expect(epki.encryptionAlgorithm).toEqual(algorithm)
        expect(epki.encryptedData.bytes).toEqual(encryptedData.bytes)
    })

    test('can be created with Uint8Array', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13', // PBES2
        })
        const encryptedData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

        const epki = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        expect(epki).toBeInstanceOf(EncryptedPrivateKeyInfo)
        expect(epki.encryptionAlgorithm).toEqual(algorithm)
        expect(epki.encryptedData.bytes).toEqual(encryptedData)
    })

    test('has correct pemHeader', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13',
        })
        const encryptedData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

        const epki = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        expect(epki.pemHeader).toEqual('ENCRYPTED PRIVATE KEY')
    })

    test('can be converted to ASN.1', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13', // PBES2
        })
        const encryptedData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

        const epki = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        const asn1 = epki.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toEqual(2)

        // First element should be the encryption algorithm (a Sequence)
        expect(asn1.valueBlock.value[0]).toBeInstanceOf(asn1js.Sequence)

        // Second element should be the encrypted data (an OctetString)
        expect(asn1.valueBlock.value[1]).toBeInstanceOf(asn1js.OctetString)
    })

    test('can be parsed from ASN.1', () => {
        const algorithmOid = '1.2.840.113549.1.5.13' // PBES2
        const encryptedData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

        // Create ASN.1 structure manually
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: algorithmOid }),
                    ],
                }),
                new asn1js.OctetString({ valueHex: encryptedData }),
            ],
        })

        const epki = EncryptedPrivateKeyInfo.fromAsn1(asn1)

        expect(epki).toBeInstanceOf(EncryptedPrivateKeyInfo)
        expect(epki.encryptionAlgorithm.algorithm.toString()).toEqual(
            algorithmOid,
        )
        expect(epki.encryptedData.bytes).toEqual(encryptedData)
    })

    test('throws an error when parsing invalid ASN.1', () => {
        // Create an ASN.1 structure that's not a SEQUENCE
        const asn1 = new asn1js.OctetString({
            valueHex: new Uint8Array([1, 2, 3]),
        })

        expect(() => EncryptedPrivateKeyInfo.fromAsn1(asn1)).toThrow(
            'EncryptedPrivateKeyInfo: expected SEQUENCE',
        )
    })

    test('can do a round-trip conversion', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13', // PBES2
        })
        const encryptedData = new Uint8Array([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ])

        const original = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        // Convert to ASN.1 and back
        const asn1 = original.toAsn1()
        const parsed = EncryptedPrivateKeyInfo.fromAsn1(asn1)

        expect(parsed.encryptionAlgorithm.algorithm.toString()).toEqual(
            original.encryptionAlgorithm.algorithm.toString(),
        )
        expect(parsed.encryptedData.bytes).toEqual(original.encryptedData.bytes)
    })

    test('can be converted to DER and back', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13', // PBES2
        })
        const encryptedData = new Uint8Array([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ])

        const original = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        // Convert to DER and back
        const der = original.toDer()
        const parsed = EncryptedPrivateKeyInfo.fromDer(der)

        expect(parsed.encryptionAlgorithm.algorithm.toString()).toEqual(
            original.encryptionAlgorithm.algorithm.toString(),
        )
        expect(parsed.encryptedData.bytes).toEqual(original.encryptedData.bytes)
    })

    test('toString snapshot', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13',
        })
        const encryptedData = new Uint8Array([
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        ])

        const epki = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        expect(epki.toString()).toMatchInlineSnapshot(`
          "[EncryptedPrivateKeyInfo] SEQUENCE :
            SEQUENCE :
              OBJECT IDENTIFIER : 1.2.840.113549.1.5.13
            OCTET STRING : 3082010a02820101"
        `)
    })

    test('toPem snapshot', () => {
        const algorithm = new ContentEncryptionAlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.13',
        })
        const encryptedData = new Uint8Array([
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        ])

        const epki = new EncryptedPrivateKeyInfo({
            encryptionAlgorithm: algorithm,
            encryptedData,
        })

        expect(epki.toPem()).toMatchInlineSnapshot(`
          "-----BEGIN ENCRYPTED PRIVATE KEY-----
          MBcwCwYJKoZIhvcNAQUNBAgwggEKAoIBAQ==
          -----END ENCRYPTED PRIVATE KEY-----"
        `)
    })
})
