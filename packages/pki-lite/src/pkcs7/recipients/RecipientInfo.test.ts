import { describe, it, expect, assert } from 'vitest'
import { RecipientInfo } from './RecipientInfo.js'
import {
    KeyAgreeRecipientInfo,
    RecipientEncryptedKeys,
} from './KeyAgreeRecipientInfo.js'
import { KEKRecipientInfo } from './KEKRecipientInfo.js'
import { PasswordRecipientInfo } from './PasswordRecipientInfo.js'
import { OtherRecipientInfo } from './OtherRecipientInfo.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { Name } from '../../x509/Name.js'
import { asn1js } from '../../core/PkiBase.js'
import { OriginatorIdentifierOrKey } from './OriginatorIdentifierOrKey.js'
import { RecipientEncryptedKey } from './RecipientEncryptedKey.js'
import { KeyIdentifier } from './KeyIdentifier.js'
import { RecipientKeyIdentifier } from './RecipientKeyIdentifier.js'
import { KEKIdentifier } from './KEKIdentifier.js'

describe('RecipientInfo', () => {
    it('should create a KeyTransRecipientInfo instance', () => {
        const issuerName: Name = new Name.RDNSequence()
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: issuerName,
            serialNumber: '1234',
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4])

        const recipientInfo = new RecipientInfo.KeyTransRecipientInfo({
            version: 0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        expect(recipientInfo).toBeInstanceOf(
            RecipientInfo.KeyTransRecipientInfo,
        )
        expect(recipientInfo.version).toEqual(0)
        expect(recipientInfo.rid).toEqual(issuerAndSerialNumber)
        expect(recipientInfo.keyEncryptionAlgorithm).toEqual(
            keyEncryptionAlgorithm,
        )
        expect(recipientInfo.encryptedKey).toEqual(encryptedKey)
    })

    it('should convert KeyTransRecipientInfo to ASN.1', () => {
        const issuerName = new Name.RDNSequence()
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: issuerName,
            serialNumber: '1234',
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4])

        const recipientInfo = new RecipientInfo.KeyTransRecipientInfo({
            version: 0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        const asn1 = recipientInfo.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.Sequence)
        const valueBlock = asn1.valueBlock as any
        expect(valueBlock.value).toHaveLength(4)
        expect(valueBlock.value[0]).toBeInstanceOf(asn1js.Integer)
        expect(valueBlock.value[3]).toBeInstanceOf(asn1js.OctetString)
    })

    it('should parse KeyTransRecipientInfo from ASN.1', () => {
        const issuerName = new Name.RDNSequence()
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: issuerName,
            serialNumber: '1234',
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.1.1',
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4])

        const originalRecipientInfo = new RecipientInfo.KeyTransRecipientInfo({
            version: 0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        const asn1 = originalRecipientInfo.toAsn1()
        const parsedRecipientInfo = RecipientInfo.fromAsn1(asn1)

        expect(parsedRecipientInfo).toBeInstanceOf(
            RecipientInfo.KeyTransRecipientInfo,
        )
        assert(
            parsedRecipientInfo instanceof RecipientInfo.KeyTransRecipientInfo,
        )
        expect(parsedRecipientInfo.version).toEqual(
            originalRecipientInfo.version,
        )

        // Compare issuerAndSerialNumber
        assert(parsedRecipientInfo.rid instanceof IssuerAndSerialNumber)
        assert(originalRecipientInfo.rid instanceof IssuerAndSerialNumber)
        expect(parsedRecipientInfo.rid.serialNumber).toEqual(
            originalRecipientInfo.rid.serialNumber,
        )

        // Compare keyEncryptionAlgorithm and encryptedKey
        expect(
            parsedRecipientInfo.keyEncryptionAlgorithm.algorithm.toString(),
        ).toEqual(
            originalRecipientInfo.keyEncryptionAlgorithm.algorithm.toString(),
        )
        expect(Array.from(parsedRecipientInfo.encryptedKey)).toEqual(
            Array.from(originalRecipientInfo.encryptedKey),
        )
    })

    it('should create a KeyAgreeRecipientInfo instance', () => {
        // Create necessary components
        const originatorPublicKey =
            new OriginatorIdentifierOrKey.OriginatorPublicKey({
                algorithm: new AlgorithmIdentifier({
                    algorithm: '1.2.840.113549.1.1.1',
                }), // RSA
                publicKey: new Uint8Array([1, 2, 3, 4]),
            })

        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.10045.2.1',
        }) // ECC

        // Create a RecipientKeyIdentifier (a type of KeyAgreeRecipientIdentifier)
        const subjectKeyIdentifier = new KeyIdentifier({
            bytes: new Uint8Array([10, 11, 12, 13]),
        })
        const recipientKeyId = new RecipientKeyIdentifier({
            subjectKeyIdentifier: subjectKeyIdentifier,
        })

        const encryptedKey = new Uint8Array([20, 21, 22, 23])
        const recipientEncryptedKey = new RecipientEncryptedKey({
            rid: recipientKeyId,
            encryptedKey: encryptedKey,
        })

        // Import RecipientEncryptedKeys to get the proper constructor
        const recipientEncryptedKeys = new RecipientEncryptedKeys(
            recipientEncryptedKey,
        )

        // Create KeyAgreeRecipientInfo
        const kari = new KeyAgreeRecipientInfo({
            version: 3,
            originator: originatorPublicKey,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            recipientEncryptedKeys: recipientEncryptedKeys,
        })

        expect(kari).toBeInstanceOf(KeyAgreeRecipientInfo)
        expect(kari.version).toEqual(3) // Always 3 for KeyAgreeRecipientInfo
        expect(kari.originator).toEqual(originatorPublicKey)
        expect(kari.keyEncryptionAlgorithm).toEqual(keyEncryptionAlgorithm)
        expect(kari.recipientEncryptedKeys).toEqual(recipientEncryptedKeys)
    })

    it('should convert KeyAgreeRecipientInfo to ASN.1 with correct tagging', () => {
        // Create necessary components
        const originatorPublicKey =
            new OriginatorIdentifierOrKey.OriginatorPublicKey({
                algorithm: new AlgorithmIdentifier({
                    algorithm: '1.2.840.113549.1.1.1',
                }), // RSA
                publicKey: new Uint8Array([1, 2, 3, 4]),
            })

        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.10045.2.1',
        }) // ECC

        // Create a RecipientKeyIdentifier (a type of KeyAgreeRecipientIdentifier)
        const subjectKeyIdentifier = new KeyIdentifier({
            bytes: new Uint8Array([10, 11, 12, 13]),
        })
        const recipientKeyId = new RecipientKeyIdentifier({
            subjectKeyIdentifier: subjectKeyIdentifier,
        })

        const encryptedKey = new Uint8Array([20, 21, 22, 23])
        const recipientEncryptedKey = new RecipientEncryptedKey({
            rid: recipientKeyId,
            encryptedKey: encryptedKey,
        })

        const recipientEncryptedKeys = new RecipientEncryptedKeys(
            recipientEncryptedKey,
        )

        // Create KeyAgreeRecipientInfo
        const kari = new KeyAgreeRecipientInfo({
            version: 0,
            originator: originatorPublicKey,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            recipientEncryptedKeys: recipientEncryptedKeys,
        })

        // Convert to ASN.1 through RecipientInfo
        const asn1 = RecipientInfo.toAsn1(kari)

        // Check that it's properly tagged
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT_SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(1) // [1]
    })

    it('should create a KEKRecipientInfo instance', () => {
        // Create necessary components
        const kekid = new KEKIdentifier({
            keyIdentifier: new Uint8Array([1, 2, 3, 4]),
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.5',
        }) // AES-256-WRAP
        const encryptedKey = new Uint8Array([5, 6, 7, 8])

        // Create KEKRecipientInfo
        const kekri = new KEKRecipientInfo({
            kekid: kekid,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        expect(kekri).toBeInstanceOf(KEKRecipientInfo)
        expect(kekri.version).toEqual(4) // Always 4 for KEKRecipientInfo
        expect(kekri.kekid).toEqual(kekid)
        expect(kekri.keyEncryptionAlgorithm).toEqual(keyEncryptionAlgorithm)
        expect(kekri.encryptedKey).toEqual(encryptedKey)
    })

    it('should convert KEKRecipientInfo to ASN.1 with correct tagging', () => {
        // Create necessary components
        const kekid = new KEKIdentifier({
            keyIdentifier: new Uint8Array([1, 2, 3, 4]),
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '2.16.840.1.101.3.4.1.5',
        }) // AES-256-WRAP
        const encryptedKey = new Uint8Array([5, 6, 7, 8])

        // Create KEKRecipientInfo
        const kekri = new KEKRecipientInfo({
            kekid: kekid,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        // Convert to ASN.1 through RecipientInfo
        const asn1 = RecipientInfo.toAsn1(kekri)

        // Check that it's properly tagged
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT_SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(2) // [2]
    })

    it('should create a PasswordRecipientInfo instance', () => {
        // Create necessary components
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.12',
        }) // PBKDF2
        const encryptedKey = new Uint8Array([9, 10, 11, 12])

        // Create PasswordRecipientInfo
        const pwri = new PasswordRecipientInfo({
            version: 0,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        expect(pwri).toBeInstanceOf(PasswordRecipientInfo)
        expect(pwri.version).toEqual(0) // Always 0 for PasswordRecipientInfo
        expect(pwri.keyEncryptionAlgorithm).toEqual(keyEncryptionAlgorithm)
        expect(pwri.encryptedKey).toEqual(encryptedKey)
    })

    it('should convert PasswordRecipientInfo to ASN.1 with correct tagging', () => {
        // Create necessary components
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: '1.2.840.113549.1.5.12',
        }) // PBKDF2
        const encryptedKey = new Uint8Array([9, 10, 11, 12])

        // Create PasswordRecipientInfo
        const pwri = new PasswordRecipientInfo({
            version: 0,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            encryptedKey: encryptedKey,
        })

        // Convert to ASN.1 through RecipientInfo
        const asn1 = RecipientInfo.toAsn1(pwri)

        // Check that it's properly tagged
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT_SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(3) // [3]
    })

    it('should create an OtherRecipientInfo instance', () => {
        // Create necessary components
        const oriType = '1.2.3.4.5' // Custom OID
        const oriValue = new asn1js.OctetString({
            valueHex: new Uint8Array([13, 14, 15, 16]),
        })

        // Create OtherRecipientInfo
        const ori = new OtherRecipientInfo({
            oriType: oriType,
            oriValue: oriValue,
        })

        expect(ori).toBeInstanceOf(OtherRecipientInfo)
        expect(ori.oriType.toString()).toEqual(oriType)
        expect(ori.oriValue).toEqual(oriValue)
    })

    it('should convert OtherRecipientInfo to ASN.1 with correct tagging', () => {
        // Create necessary components
        const oriType = '1.2.3.4.5' // Custom OID
        const oriValue = new asn1js.OctetString({
            valueHex: new Uint8Array([13, 14, 15, 16]),
        })

        // Create OtherRecipientInfo
        const ori = new OtherRecipientInfo({
            oriType: oriType,
            oriValue: oriValue,
        })

        // Convert to ASN.1 through RecipientInfo
        const asn1 = RecipientInfo.toAsn1(ori)

        // Check that it's properly tagged
        expect(asn1.idBlock.tagClass).toEqual(3) // CONTEXT_SPECIFIC
        expect(asn1.idBlock.tagNumber).toEqual(4) // [4]
    })
})
