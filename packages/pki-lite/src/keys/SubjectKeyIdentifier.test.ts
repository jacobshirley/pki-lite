import { describe, it, expect } from 'vitest'
import { SubjectKeyIdentifier } from './SubjectKeyIdentifier.js'
import { asn1js } from '../core/PkiBase.js'

describe('SubjectKeyIdentifier', () => {
    it('should create a SubjectKeyIdentifier with a Uint8Array<ArrayBuffer> value', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new SubjectKeyIdentifier({
            bytes: keyIdentifier,
        })

        expect(subjectKeyIdentifier.bytes).toEqual(keyIdentifier)
    })

    it('should convert to ASN.1 structure correctly', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new SubjectKeyIdentifier({
            bytes: keyIdentifier,
        })

        const asn1 = subjectKeyIdentifier.toAsn1()

        expect(asn1).toBeInstanceOf(asn1js.OctetString)
        // Test that it's a valid OctetString with non-zero length
        expect(asn1.valueBlock).toBeDefined()
    })

    it('should create from ASN.1 structure correctly', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const octetString = new asn1js.OctetString({ valueHex: keyIdentifier })

        const subjectKeyIdentifier = SubjectKeyIdentifier.fromAsn1(octetString)

        expect(subjectKeyIdentifier).toBeInstanceOf(SubjectKeyIdentifier)
        expect(Array.from(subjectKeyIdentifier.bytes)).toEqual(
            Array.from(keyIdentifier),
        )
    })

    it('should throw an error when creating from an invalid ASN.1 structure', () => {
        const integer = new asn1js.Integer({ value: 123 })

        expect(() => SubjectKeyIdentifier.fromAsn1(integer)).toThrow(
            'Invalid ASN.1 structure for SubjectKeyIdentifier',
        )
    })

    it('should correctly encode and decode a SubjectKeyIdentifier', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const originalSubjectKeyIdentifier = new SubjectKeyIdentifier({
            bytes: keyIdentifier,
        })

        // Explicitly encode to DER and then decode back to ASN.1
        const der = originalSubjectKeyIdentifier.toDer()
        const asn1 = asn1js.fromBER(der).result

        // Now decode the ASN.1 to a SubjectKeyIdentifier
        const decodedSubjectKeyIdentifier = SubjectKeyIdentifier.fromAsn1(asn1)

        expect(decodedSubjectKeyIdentifier).toBeInstanceOf(SubjectKeyIdentifier)
        expect(decodedSubjectKeyIdentifier.bytes).toBeDefined()
        expect(decodedSubjectKeyIdentifier.bytes.byteLength).toEqual(
            keyIdentifier.length,
        )

        // Compare the arrays byte by byte
        const original = Array.from(keyIdentifier)
        const decoded = Array.from(decodedSubjectKeyIdentifier.bytes)
        expect(decoded).toEqual(original)
    })

    it('should create a valid DER representation', () => {
        const keyIdentifier = new Uint8Array([1, 2, 3, 4, 5])
        const subjectKeyIdentifier = new SubjectKeyIdentifier({
            bytes: keyIdentifier,
        })

        const der = subjectKeyIdentifier.toDer()

        expect(der).toBeInstanceOf(Uint8Array<ArrayBuffer>)
        expect(der.length).toBeGreaterThan(0)

        // The DER encoding of an OCTET STRING starts with tag 0x04
        expect(der[0]).toEqual(0x04)

        // Check length byte and content
        expect(der[1]).toEqual(keyIdentifier.length)
        expect(Array.from(der.slice(2, 2 + keyIdentifier.length))).toEqual(
            Array.from(keyIdentifier),
        )
    })
})
