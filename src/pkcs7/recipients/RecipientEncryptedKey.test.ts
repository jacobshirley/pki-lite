import { describe, it, expect } from 'vitest'
import { RecipientEncryptedKey } from './RecipientEncryptedKey.js'
import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { RDNSequence } from '../../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../../x509/AttributeTypeAndValue.js'
import { OIDs } from '../../core/OIDs.js'
import { Name } from '../../x509/Name.js'

describe('RecipientEncryptedKey', () => {
    it('should convert to and from ASN.1', () => {
        const rdn = new RelativeDistinguishedName(
            new AttributeTypeAndValue({ type: OIDs.DN.CN, value: 'Test' }),
        )
        const issuer = new RDNSequence(rdn)
        const issuerAndSerialNumber = new IssuerAndSerialNumber({
            issuer: Name.fromAsn1(issuer.toAsn1()),
            serialNumber: 1,
        })
        const encryptedKey = new Uint8Array([1, 2, 3, 4])

        const original = new RecipientEncryptedKey({
            rid: issuerAndSerialNumber,
            encryptedKey,
        })

        const asn1 = original.toAsn1()
        const restored = RecipientEncryptedKey.fromAsn1(asn1)

        expect(restored).toBeInstanceOf(RecipientEncryptedKey)
        expect(restored.encryptedKey).toEqual(original.encryptedKey)
    })
})
