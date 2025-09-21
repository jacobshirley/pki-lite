import { test, expect, describe } from 'vitest'
import { ResponderID, KeyHash } from './ResponderID.js'
import { RDNSequence } from '../x509/RDNSequence.js'
import { RelativeDistinguishedName } from '../x509/RelativeDistinguishedName.js'
import { AttributeTypeAndValue } from '../x509/AttributeTypeAndValue.js'
import { OIDs } from '../core/OIDs.js'
import { asn1js } from '../core/PkiBase.js'

describe('ResponderID', () => {
    test('should create a ResponderID byName', () => {
        // Create a sample Name object (RDNSequence)
        const rdnSequence = new RDNSequence()

        // Create a RelativeDistinguishedName with a CN attribute
        const rdn = new RelativeDistinguishedName()
        const commonNameAttr = new AttributeTypeAndValue({
            type: OIDs.DN.CN,
            value: 'Test OCSP Responder',
        })
        rdn.push(commonNameAttr)
        rdnSequence.push(rdn)

        // Create ResponderID with name (RDNSequence)
        const responderIdByName = rdnSequence

        // Verify ASN.1 encoding
        const asn1 = ResponderID.toAsn1(responderIdByName)
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(1) // [1]

        // Verify decoding works
        const decoded = ResponderID.fromAsn1(asn1)
        expect(decoded).toBeInstanceOf(RDNSequence)
    })

    test('should create a ResponderID byKey', () => {
        // Create a sample KeyHash (SHA-1 hash is 20 bytes)
        const keyHashBytes = new Uint8Array(20)
        // Fill with some test values
        for (let i = 0; i < 20; i++) {
            keyHashBytes[i] = i
        }
        const keyHash = new KeyHash({ bytes: keyHashBytes })

        // Verify ASN.1 encoding
        const asn1 = ResponderID.toAsn1(keyHash)
        expect(asn1).toBeInstanceOf(asn1js.Constructed)
        expect(asn1.idBlock.tagClass).toBe(3) // CONTEXT-SPECIFIC
        expect(asn1.idBlock.tagNumber).toBe(2) // [2]

        // Verify decoding
        const decoded = ResponderID.fromAsn1(asn1)
        expect(decoded).toBeInstanceOf(KeyHash)
    })

    test('should throw error for invalid ASN.1 structure', () => {
        // Create an invalid ASN.1 structure (wrong tag number)
        const invalidAsn1 = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // CONTEXT-SPECIFIC
                tagNumber: 3, // [3] - invalid for ResponderID
            },
            value: [],
        })

        // Verify error is thrown
        expect(() => ResponderID.fromAsn1(invalidAsn1)).toThrow(
            'Invalid ASN.1 structure for ResponderID',
        )
    })

    test('should round-trip ResponderID byName through ASN.1', () => {
        // Create a more complex name with multiple RDNs
        const rdnSequence = new RDNSequence()

        // Add CN RDN
        const cnRdn = new RelativeDistinguishedName()
        const cnAttr = new AttributeTypeAndValue({
            type: OIDs.DN.CN,
            value: 'OCSP Responder',
        })
        cnRdn.push(cnAttr)
        rdnSequence.push(cnRdn)

        // Add Organization RDN
        const orgRdn = new RelativeDistinguishedName()
        const orgAttr = new AttributeTypeAndValue({
            type: OIDs.DN.O,
            value: 'Example CA',
        })
        orgRdn.push(orgAttr)
        rdnSequence.push(orgRdn)

        // Encode to ASN.1 and decode back
        const asn1 = ResponderID.toAsn1(rdnSequence)
        const decoded = ResponderID.fromAsn1(asn1)

        // Verify the decoded object is an RDNSequence
        expect(decoded).toBeInstanceOf(RDNSequence)
    })

    test('should round-trip ResponderID byKey through ASN.1', () => {
        // Create a key hash with specific bytes
        const keyHashBytes = new Uint8Array([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ])
        const keyHash = new KeyHash({ bytes: keyHashBytes })

        // Encode to ASN.1 and decode back
        const asn1 = ResponderID.toAsn1(keyHash)
        const decoded = ResponderID.fromAsn1(asn1)

        // Verify the decoded object is a KeyHash
        expect(decoded).toBeInstanceOf(KeyHash)

        // Verify bytes were preserved
        if (decoded instanceof KeyHash) {
            expect(decoded.bytes).toEqual(keyHashBytes)
        }
    })
})
