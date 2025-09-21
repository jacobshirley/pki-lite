import { describe, it, expect } from 'vitest'
import {
    SigPolicyQualifierInfo,
    OtherHashAlgAndValue,
    SignaturePolicyId,
    SignaturePolicyIdentifier,
} from './SignaturePolicyIdentifier.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import { AlgorithmIdentifier } from '../../algorithms/AlgorithmIdentifier.js'
import { asn1js } from '../../core/PkiBase.js'

function makeAlgorithmIdentifier() {
    return new AlgorithmIdentifier({
        algorithm: new ObjectIdentifier({ value: '2.16.840.1.101.3.4.2.1' }), // sha256
    })
}

describe('SigPolicyQualifierInfo', () => {
    it('should encode and decode ASN.1 correctly', () => {
        const oid = new ObjectIdentifier({ value: '1.3.6.1.5.5.7.2.1' })
        const qualifier = new Uint8Array([
            0x13,
            0x0b,
            ...new TextEncoder().encode('http://cps'),
        ])
        const info = new SigPolicyQualifierInfo({
            sigPolicyQualifierId: oid,
            sigQualifier: qualifier,
        })
        const asn1 = info.toAsn1()
        const decoded = SigPolicyQualifierInfo.fromAsn1(asn1)
        expect(decoded.sigPolicyQualifierId.value).toBe('1.3.6.1.5.5.7.2.1')
        expect(decoded.sigQualifier.derBytes![0]).toBe(0x13) // IA5String tag
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() =>
            SigPolicyQualifierInfo.fromAsn1(new asn1js.Null()),
        ).toThrow('Expected Sequence with at least 2 elements')
    })
})

describe('OtherHashAlgAndValue', () => {
    it('should encode and decode ASN.1 correctly', () => {
        const hashAlg = makeAlgorithmIdentifier()
        const hashValue = new Uint8Array([1, 2, 3, 4])
        const other = new OtherHashAlgAndValue({
            hashAlgorithm: hashAlg,
            hashValue,
        })
        const asn1 = other.toAsn1()
        const decoded = OtherHashAlgAndValue.fromAsn1(asn1)
        expect(decoded.hashAlgorithm.algorithm.value).toBe(
            '2.16.840.1.101.3.4.2.1',
        )
        expect(decoded.hashValue.bytes).toEqual(new Uint8Array([1, 2, 3, 4]))
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() => OtherHashAlgAndValue.fromAsn1(new asn1js.Null())).toThrow(
            'Expected Sequence with at least 2 elements',
        )
    })
})

describe('SignaturePolicyId', () => {
    it('should encode and decode ASN.1 correctly (no qualifiers)', () => {
        const hashAlg = makeAlgorithmIdentifier()
        const hashValue = new Uint8Array([1, 2, 3, 4])
        const other = new OtherHashAlgAndValue({
            hashAlgorithm: hashAlg,
            hashValue,
        })
        const sigPolicyId = new SignaturePolicyId({
            sigPolicyId: '1.2.3.4.5',
            sigPolicyHash: other,
        })
        const asn1 = sigPolicyId.toAsn1()
        const decoded = SignaturePolicyId.fromAsn1(asn1)
        expect(decoded.sigPolicyId.value).toBe('1.2.3.4.5')
        expect(decoded.sigPolicyHash.hashValue.bytes).toEqual(
            new Uint8Array([1, 2, 3, 4]),
        )
        expect(decoded.sigPolicyQualifiers).toBeUndefined()
    })

    it('should throw if ASN.1 is not a sequence', () => {
        expect(() => SignaturePolicyId.fromAsn1(new asn1js.Null())).toThrow(
            'Expected Sequence with at least 2 elements',
        )
    })
})

describe('SignaturePolicyIdentifier', () => {
    it('should encode and decode implied (null) value', () => {
        const asn1 = SignaturePolicyIdentifier.toAsn1(null)
        const decoded = SignaturePolicyIdentifier.fromAsn1(asn1)
        expect(decoded).toBeNull()
    })

    it('should encode and decode signaturePolicyId value', () => {
        const hashAlg = makeAlgorithmIdentifier()
        const hashValue = new Uint8Array([1, 2, 3, 4])
        const other = new OtherHashAlgAndValue({
            hashAlgorithm: hashAlg,
            hashValue,
        })
        const sigPolicyId = new SignaturePolicyId({
            sigPolicyId: '1.2.3.4.5',
            sigPolicyHash: other,
        })
        const asn1 = SignaturePolicyIdentifier.toAsn1(sigPolicyId)
        const decoded = SignaturePolicyIdentifier.fromAsn1(asn1)
        expect(decoded).not.toBeNull()
        if (decoded && decoded instanceof SignaturePolicyId) {
            expect(decoded.sigPolicyId.value).toBe('1.2.3.4.5')
        }
    })
})
