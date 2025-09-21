import { describe, it, expect } from 'vitest'
import {
    KeyAgreeRecipientInfo,
    RecipientEncryptedKeys,
} from './KeyAgreeRecipientInfo.js'
import { CMSVersion } from '../CMSVersion.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { SubjectKeyIdentifier } from '../../keys/SubjectKeyIdentifier.js'
import { RecipientEncryptedKey } from './RecipientEncryptedKey.js'
import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { RDNSequence } from '../../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../../x509/AttributeTypeAndValue.js'
import { OIDs } from '../../core/OIDs.js'
import { Name } from '../../x509/Name.js'

describe('KeyAgreeRecipientInfo', () => {
    it('should convert to and from ASN.1', () => {
        const originator = new SubjectKeyIdentifier({
            bytes: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        })
        const keyEncryptionAlgorithm = new AlgorithmIdentifier({
            algorithm: OIDs.RSA.ENCRYPTION,
        })

        const rdn = new RelativeDistinguishedName(
            new AttributeTypeAndValue({ type: OIDs.DN.CN, value: 'Test' }),
        )
        const issuer = new RDNSequence(rdn)

        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: Name.fromAsn1(issuer.toAsn1()),
            serialNumber: 1,
        })

        const encryptedKey = new Uint8Array([1, 2, 3, 4])
        const recipientEncryptedKey = new RecipientEncryptedKey({
            rid: issuerAndSerialNumber,
            encryptedKey,
        })
        const recipientEncryptedKeys = new RecipientEncryptedKeys(
            recipientEncryptedKey,
        )
        const ukm = new Uint8Array([9, 8, 7, 6])

        const original = new KeyAgreeRecipientInfo({
            version: CMSVersion.v3,
            originator,
            keyEncryptionAlgorithm,
            recipientEncryptedKeys,
            ukm,
        })

        const asn1 = original.toAsn1()
        const restored = KeyAgreeRecipientInfo.fromAsn1(asn1)

        expect(restored).toBeInstanceOf(KeyAgreeRecipientInfo)
        expect(restored.version).toBe(original.version)
        expect(restored.ukm).toEqual(original.ukm)

        expect(restored.keyEncryptionAlgorithm.algorithm).toEqual(
            original.keyEncryptionAlgorithm.algorithm,
        )

        const restoredOriginator = restored.originator as SubjectKeyIdentifier
        expect(restoredOriginator.bytes).toEqual(
            (original.originator as SubjectKeyIdentifier).bytes,
        )

        expect(restored.recipientEncryptedKeys.length).toBe(1)
        const restoredRek = restored.recipientEncryptedKeys[0]
        expect(restoredRek.encryptedKey).toEqual(
            recipientEncryptedKey.encryptedKey,
        )
    })
})
