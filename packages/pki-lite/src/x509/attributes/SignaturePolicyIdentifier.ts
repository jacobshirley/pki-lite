import {
    AlgorithmIdentifier,
    DigestAlgorithmIdentifier,
} from '../../algorithms/AlgorithmIdentifier.js'
import { Any } from '../../asn1/Any.js'
import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import { OctetString } from '../../asn1/OctetString.js'
import {
    Asn1Any,
    Asn1Node,
    Choice,
    der,
    ObjectIdentifierString,
    PkiBase,
    UniversalTag,
} from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents a SigPolicyQualifierInfo.
 *
 * @asn
 * ```asn
 * SigPolicyQualifierInfo ::= SEQUENCE {
 *         sigPolicyQualifierId  SigPolicyQualifierId,
 *         sigQualifier          ANY DEFINED BY sigPolicyQualifierId
 * }
 * SigPolicyQualifierId ::= OBJECT IDENTIFIER
 * ```
 */
export class SigPolicyQualifierInfo extends PkiBase<SigPolicyQualifierInfo> {
    sigPolicyQualifierId: ObjectIdentifier
    sigQualifier: Any

    constructor(options: {
        sigPolicyQualifierId: ObjectIdentifier
        sigQualifier: Asn1Any
    }) {
        super()
        this.sigPolicyQualifierId = options.sigPolicyQualifierId
        this.sigQualifier = new Any({ derBytes: options.sigQualifier })
    }

    toAsn1(): Asn1Node {
        return der.sequence([
            this.sigPolicyQualifierId.toAsn1(),
            this.sigQualifier.toAsn1(),
        ])
    }

    static fromAsn1(asn1: Asn1Node): SigPolicyQualifierInfo {
        if (!asn1.is(UniversalTag.Sequence) || asn1.children.length < 2) {
            throw new Asn1ParseError(
                'Expected Sequence with at least 2 elements',
            )
        }

        const sigPolicyQualifierId = ObjectIdentifier.fromAsn1(asn1.children[0])
        const sigQualifier = new Any({
            derBytes: asn1.children[1].encode(),
        })

        return new SigPolicyQualifierInfo({
            sigPolicyQualifierId,
            sigQualifier,
        })
    }
}

/**
 * Represents a SigPolicyHash.
 *
 * @asn
 * ```asn
 * OtherHashAlgAndValue ::= SEQUENCE {
 *        hashAlgorithm   AlgorithmIdentifier,
 *        hashValue       OtherHashValue
 * }
 * OtherHashValue ::= OCTET STRING
 */
export class OtherHashAlgAndValue extends PkiBase<OtherHashAlgAndValue> {
    hashAlgorithm: AlgorithmIdentifier
    hashValue: OctetString

    constructor(options: {
        hashAlgorithm: AlgorithmIdentifier
        hashValue: Uint8Array<ArrayBuffer> | OctetString
    }) {
        super()
        this.hashAlgorithm = options.hashAlgorithm
        this.hashValue = new OctetString({ bytes: options.hashValue })
    }

    toAsn1(): Asn1Node {
        return der.sequence([
            this.hashAlgorithm.toAsn1(),
            this.hashValue.toAsn1(),
        ])
    }

    static fromAsn1(asn1: Asn1Node): OtherHashAlgAndValue {
        if (!asn1.is(UniversalTag.Sequence) || asn1.children.length < 2) {
            throw new Asn1ParseError(
                'Expected Sequence with at least 2 elements',
            )
        }

        const hashAlgorithm = DigestAlgorithmIdentifier.fromAsn1(
            asn1.children[0],
        )
        const hashValue = OctetString.fromAsn1(asn1.children[1])

        return new OtherHashAlgAndValue({
            hashAlgorithm,
            hashValue,
        })
    }
}

/**
 * Represents a SignaturePolicyId.
 *
 * @asn
 * ```asn
 * SignaturePolicyId ::= SEQUENCE {
 *    sigPolicyId           SigPolicyId,
 *    sigPolicyHash         SigPolicyHash
 *    sigPolicyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                            SigPolicyQualifierInfo OPTIONAL
 * }
 * SigPolicyId ::= OBJECT IDENTIFIER
 */
export class SignaturePolicyId extends PkiBase<SignaturePolicyId> {
    sigPolicyId: ObjectIdentifier
    sigPolicyHash: OtherHashAlgAndValue
    sigPolicyQualifiers?: SigPolicyQualifierInfo[]

    constructor(options: {
        sigPolicyId: ObjectIdentifier | ObjectIdentifierString
        sigPolicyHash: OtherHashAlgAndValue
        sigPolicyQualifiers?: SigPolicyQualifierInfo[]
    }) {
        super()
        this.sigPolicyId = new ObjectIdentifier({ value: options.sigPolicyId })
        this.sigPolicyHash = options.sigPolicyHash
        this.sigPolicyQualifiers = options.sigPolicyQualifiers
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [
            this.sigPolicyId.toAsn1(),
            this.sigPolicyHash.toAsn1(),
        ]

        if (this.sigPolicyQualifiers && this.sigPolicyQualifiers.length > 0) {
            values.push(
                der.sequence(this.sigPolicyQualifiers.map((q) => q.toAsn1())),
            )
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): SignaturePolicyId {
        if (!asn1.is(UniversalTag.Sequence) || asn1.children.length < 2) {
            throw new Asn1ParseError(
                'Expected Sequence with at least 2 elements',
            )
        }

        const sigPolicyId = ObjectIdentifier.fromAsn1(asn1.children[0])
        const sigPolicyHash = OtherHashAlgAndValue.fromAsn1(asn1.children[1])

        return new SignaturePolicyId({
            sigPolicyId,
            sigPolicyHash,
        })
    }
}

/**
 * Represents a SignaturePolicyIdentifier attribute.
 *
 * @asn
 * ```asn
 * SignaturePolicyIdentifier ::= CHOICE {
 *    signaturePolicyId          SignaturePolicyId,
 *    signaturePolicyImplied     SignaturePolicyImplied
 *                               -- not used in this version
 * }
 *
 * SignaturePolicyImplied ::= NULL
 */
export type SignaturePolicyIdentifier = SignaturePolicyId | null
export const SignaturePolicyIdentifier = Choice('SignaturePolicyIdentifier', {
    signaturePolicyId: SignaturePolicyId,
    signaturePolicyImplied: null,
    fromAsn1(asn1: Asn1Node): SignaturePolicyIdentifier {
        if (asn1.is(UniversalTag.Null)) {
            return null
        } else {
            return SignaturePolicyId.fromAsn1(asn1)
        }
    },
    toAsn1(value: SignaturePolicyIdentifier): Asn1Node {
        if (value === null) {
            return der.nullValue()
        } else {
            return value.toAsn1()
        }
    },
})
