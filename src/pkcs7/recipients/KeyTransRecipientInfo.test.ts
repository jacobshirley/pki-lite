import { describe, expect, it } from 'vitest'
import { KeyTransRecipientInfo } from './KeyTransRecipientInfo.js'
import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../../core/OIDs.js'
import { SubjectKeyIdentifier } from '../../keys/SubjectKeyIdentifier.js'
import { RDNSequence } from '../../x509/RDNSequence.js'
import { Integer } from '../../asn1/Integer.js'

describe('KeyTransRecipientInfo', () => {
    it('should create with issuerAndSerialNumber and set version to 0', () => {
        const issuer = new RDNSequence()
        const serialNumber = new Integer({ value: 123456789 })
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer,
            serialNumber,
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.RSA.RSAES_OAEP,
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4, 5])

        const ktri = new KeyTransRecipientInfo({
            version: 0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm,
            encryptedKey,
        })

        expect(ktri.version).toBe(0)
        expect(ktri.rid).toBe(issuerAndSerialNumber)
        expect(ktri.keyEncryptionAlgorithm).toEqual(keyEncryptionAlgorithm)
        expect(ktri.encryptedKey).toBe(encryptedKey)
    })

    it('should create with subjectKeyIdentifier and set version to 2', () => {
        const keyId = new Uint8Array([10, 11, 12, 13, 14, 15])
        const subjectKeyIdentifier = new SubjectKeyIdentifier({
            bytes: keyId,
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.RSA.RSAES_OAEP,
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4, 5])

        const ktri = new KeyTransRecipientInfo({
            version: 2,
            rid: subjectKeyIdentifier,
            keyEncryptionAlgorithm,
            encryptedKey,
        })

        expect(ktri.version).toBe(2)
        expect(ktri.rid).toBe(subjectKeyIdentifier)
        expect(ktri.keyEncryptionAlgorithm).toEqual(keyEncryptionAlgorithm)
        expect(ktri.encryptedKey).toBe(encryptedKey)
    })

    it('should encode and decode with issuerAndSerialNumber', () => {
        const issuer = new RDNSequence()
        const serialNumber = new Integer({ value: 123456789 })
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer,
            serialNumber,
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.RSA.RSAES_OAEP,
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4, 5])

        const original = new KeyTransRecipientInfo({
            version: 0,
            rid: issuerAndSerialNumber,
            keyEncryptionAlgorithm,
            encryptedKey,
        })

        const asn1 = original.toAsn1()
        const decoded = KeyTransRecipientInfo.fromAsn1(asn1)

        expect(decoded.version).toBe(0)
        expect(decoded.keyEncryptionAlgorithm.algorithm.toString()).toBe(
            OIDs.RSA.RSAES_OAEP,
        )
        expect(decoded.encryptedKey).toEqual(encryptedKey)
        expect(decoded.rid instanceof IssuerAndSerialNumber).toBe(true)
    })

    it('should encode and decode with subjectKeyIdentifier', () => {
        const keyId = new Uint8Array([10, 11, 12, 13, 14, 15])
        const subjectKeyIdentifier = new SubjectKeyIdentifier({
            bytes: keyId,
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.RSA.RSAES_OAEP,
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4, 5])

        const original = new KeyTransRecipientInfo({
            version: 1,
            rid: subjectKeyIdentifier,
            keyEncryptionAlgorithm,
            encryptedKey,
        })

        const asn1 = original.toAsn1()
        const decoded = KeyTransRecipientInfo.fromAsn1(asn1)

        expect(decoded.version).toBe(1)
        expect(decoded.keyEncryptionAlgorithm.algorithm.toString()).toBe(
            OIDs.RSA.RSAES_OAEP,
        )
        expect(decoded.encryptedKey).toEqual(encryptedKey)
        expect(decoded.rid instanceof SubjectKeyIdentifier).toBe(true)

        const skid = decoded.rid as SubjectKeyIdentifier
        expect(skid.bytes).toEqual(keyId)
    })
})
