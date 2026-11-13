import { assert, describe, expect, test } from 'vitest'
import { KEKRecipientInfo } from './KEKRecipientInfo.js'
import { KEKIdentifier } from './KEKIdentifier.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { der, UniversalTag } from '../../core/PkiBase.js'
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
        expect(kekRecipientInfo.version).toEqual(CMSVersion.v4)
        expect(kekRecipientInfo.kekid).toEqual(kekId)
        expect(kekRecipientInfo.keyEncryptionAlgorithm).toEqual(algorithm)
        expect(kekRecipientInfo.encryptedKey).toEqual(encryptedKey)
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

        assert(asn1.is(UniversalTag.Sequence))
        expect(asn1.children.length).toEqual(4)

        // Check version
        const versionBlock = asn1.children[0]
        assert(versionBlock.is(UniversalTag.Integer))
        expect(der.readNumber(versionBlock)).toEqual(CMSVersion.v4)

        // Check kekid
        const kekidBlock = asn1.children[1]
        assert(kekidBlock.is(UniversalTag.Sequence))

        // Check keyEncryptionAlgorithm
        const algorithmBlock = asn1.children[2]
        assert(algorithmBlock.is(UniversalTag.Sequence))

        // Check encryptedKey
        const encryptedKeyBlock = asn1.children[3]
        assert(encryptedKeyBlock.is(UniversalTag.OctetString))
        expect(encryptedKeyBlock.bytes()).toEqual(encryptedKey)
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
        expect(parsed.version).toEqual(CMSVersion.v4)
        expect(parsed.kekid).toBeInstanceOf(KEKIdentifier)
        expect(parsed.kekid.keyIdentifier).toEqual(keyIdentifier)
        expect(parsed.keyEncryptionAlgorithm).toBeInstanceOf(
            AlgorithmIdentifier,
        )
        expect(parsed.keyEncryptionAlgorithm.algorithm.toString()).toEqual(
            '1.2.840.113549.3.7',
        )
        expect(parsed.encryptedKey).toEqual(encryptedKey)
    })

    test('throws error on invalid ASN.1 structure type', () => {
        const asn1 = der.integer(1)
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Sequence for KEKRecipientInfo',
        )
    })

    test('throws error on invalid ASN.1 structure element count', () => {
        const asn1 = der.sequence([
            der.integer(1),
            der.integer(2),
            der.integer(3),
        ])
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected 4 elements, got 3',
        )
    })

    test('throws error on invalid version type', () => {
        const asn1 = der.sequence([
            der.octetString(new Uint8Array([1])),
            der.sequence([]),
            der.sequence([]),
            der.octetString(new Uint8Array([1])),
        ])
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected Integer for version',
        )
    })

    test('throws error on invalid version value', () => {
        const asn1 = der.sequence([
            der.integer(1), // Wrong version
            der.sequence([der.octetString(new Uint8Array([1]))]),
            der.sequence([der.oid('1.2.840.113549.3.7')]),
            der.octetString(new Uint8Array([1])),
        ])
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid version: expected 4, got 1',
        )
    })

    test('throws error on invalid encryptedKey type', () => {
        const asn1 = der.sequence([
            der.integer(4),
            der.sequence([der.octetString(new Uint8Array([1]))]),
            der.sequence([der.oid('1.2.840.113549.3.7')]),
            der.integer(1), // Wrong type
        ])
        expect(() => KEKRecipientInfo.fromAsn1(asn1)).toThrow(
            'Invalid ASN.1 structure: expected OctetString for encryptedKey',
        )
    })
})
