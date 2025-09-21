import { assert, describe, expect, test } from 'vitest'
import { KEKRecipientInfo } from './KEKRecipientInfo.js'
import { KEKIdentifier } from './KEKIdentifier.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../../core/PkiBase.js'
import { CMSVersion } from '../CMSVersion.js'

describe('KEKRecipientInfo', () => {
    test('can be created', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const kekId = new KEKIdentifier({ keyIdentifier: keyIdentifier })
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.3.7',
        }) // DES-EDE3-CBC
        const encryptedKey = new Uint8Array([10, 11, 12, 13, 14])

        const kekRecipientInfo = new KEKRecipientInfo({
            kekid: kekId,
            keyEncryptionAlgorithm: algorithm,
            encryptedKey: encryptedKey,
        })

        expect(kekRecipientInfo).toBeInstanceOf(KEKRecipientInfo)
        expect(kekRecipientInfo.version).toBe(CMSVersion.v4)
        expect(kekRecipientInfo.kekid).toBe(kekId)
        expect(kekRecipientInfo.keyEncryptionAlgorithm).toBe(algorithm)
        expect(kekRecipientInfo.encryptedKey).toBe(encryptedKey)
    })

    test('can be converted to ASN.1', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const kekId = new KEKIdentifier({ keyIdentifier: keyIdentifier })
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.3.7',
        }) // DES-EDE3-CBC
        const encryptedKey = new Uint8Array([10, 11, 12, 13, 14])

        const kekRecipientInfo = new KEKRecipientInfo({
            kekid: kekId,
            keyEncryptionAlgorithm: algorithm,
            encryptedKey: encryptedKey,
        })
        const asn1 = kekRecipientInfo.toAsn1()

        assert(asn1 instanceof asn1js.Sequence)
        expect(asn1.valueBlock.value.length).toBe(4)

        // Check version
        const versionBlock = asn1.valueBlock.value[0]
        assert(versionBlock instanceof asn1js.Integer)
        expect(versionBlock.valueBlock.valueDec).toBe(CMSVersion.v4)

        // Check kekid
        const kekidBlock = asn1.valueBlock.value[1]
        assert(kekidBlock instanceof asn1js.Sequence)

        // Check keyEncryptionAlgorithm
        const algorithmBlock = asn1.valueBlock.value[2]
        assert(algorithmBlock instanceof asn1js.Sequence)

        // Check encryptedKey
        const encryptedKeyBlock = asn1.valueBlock.value[3]
        assert(encryptedKeyBlock instanceof asn1js.OctetString)
        expect(
            new Uint8Array(encryptedKeyBlock.valueBlock.valueHexView),
        ).toEqual(encryptedKey)
    })

    test('can be parsed from ASN.1', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const kekId = new KEKIdentifier({ keyIdentifier: keyIdentifier })
        const algorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.3.7',
        }) // DES-EDE3-CBC
        const encryptedKey = new Uint8Array([10, 11, 12, 13, 14])

        const kekRecipientInfo = new KEKRecipientInfo({
            kekid: kekId,
            keyEncryptionAlgorithm: algorithm,
            encryptedKey: encryptedKey,
        })
        const asn1 = kekRecipientInfo.toAsn1()
        const parsed = KEKRecipientInfo.fromAsn1(asn1)

        expect(parsed).toBeInstanceOf(KEKRecipientInfo)
        expect(parsed.version).toBe(CMSVersion.v4)
        expect(parsed.kekid).toBeInstanceOf(KEKIdentifier)
        expect(parsed.kekid.keyIdentifier).toEqual(keyIdentifier)
        expect(parsed.keyEncryptionAlgorithm).toBeInstanceOf(
            AlgorithmIdentifier,
        )
        expect(parsed.keyEncryptionAlgorithm.algorithm.toString()).toBe(
            '1.2.840.113549.3.7',
        )
        expect(parsed.encryptedKey).toEqual(encryptedKey)
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = new asn1js.Integer({ value: 1 })
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for KEKRecipientInfo',
        )
    })

    test('throws error on invalid ASN.1 structure element count', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }),
                new asn1js.Integer({ value: 2 }),
                new asn1js.Integer({ value: 3 }),
            ],
        })
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 4 elements, got 3',
        )
    })

    test('throws error on invalid version type', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.OctetString({ valueHex: new Uint8Array([1]) }),
                new asn1js.Sequence({ value: [] }),
                new asn1js.Sequence({ value: [] }),
                new asn1js.OctetString({ valueHex: new Uint8Array([1]) }),
            ],
        })
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Integer for version',
        )
    })

    test('throws error on invalid version value', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 1 }), // Wrong version
                new asn1js.Sequence({
                    value: [
                        new asn1js.OctetString({
                            valueHex: new Uint8Array([1]),
                        }),
                    ],
                }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({
                            value: '1.2.840.113549.3.7',
                        }),
                    ],
                }),
                new asn1js.OctetString({ valueHex: new Uint8Array([1]) }),
            ],
        })
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid version: expected 4, got 1',
        )
    })

    test('throws error on invalid encryptedKey type', () => {
        const asn1 = new asn1js.Sequence({
            value: [
                new asn1js.Integer({ value: 4 }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.OctetString({
                            valueHex: new Uint8Array([1]),
                        }),
                    ],
                }),
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({
                            value: '1.2.840.113549.3.7',
                        }),
                    ],
                }),
                new asn1js.Integer({ value: 1 }), // Wrong type
            ],
        })
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected OctetString for encryptedKey',
        )
    })
})
