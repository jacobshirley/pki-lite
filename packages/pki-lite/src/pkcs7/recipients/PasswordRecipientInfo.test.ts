import { describe, it, expect } from 'vitest'
import { PasswordRecipientInfo } from './PasswordRecipientInfo.js'
import { CMSVersion } from '../CMSVersion.js'
import { KeyEncryptionAlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { OIDs } from '../../core/OIDs.js'

describe('PasswordRecipientInfo', () => {
    it('should convert to and from ASN.1', () => {
        const keyEncryptionAlgorithm = new KeyEncryptionAlgorithmIdentifier({
            algorithm: OIDs.PKCS5.PBES2,
        })

        const encryptedKey = new Uint8Array([1, 2, 3, 4])
        const original = new PasswordRecipientInfo({
            version: CMSVersion.v0,
            keyEncryptionAlgorithm,
            encryptedKey,
        })

        const asn1 = original.toAsn1()
        const restored = PasswordRecipientInfo.fromAsn1(asn1)

        expect(restored).toBeInstanceOf(PasswordRecipientInfo)
        expect(restored.version).toBe(original.version)
        expect(restored.keyDerivationAlgorithm).toEqual(
            original.keyDerivationAlgorithm,
        )
        expect(restored.keyEncryptionAlgorithm.algorithm).toEqual(
            original.keyEncryptionAlgorithm.algorithm,
        )
        expect(restored.encryptedKey).toEqual(original.encryptedKey)
    })
})
