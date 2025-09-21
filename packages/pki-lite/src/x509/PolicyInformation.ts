import { Any } from '../asn1/Any.js'
import { ObjectIdentifier } from '../asn1/ObjectIdentifier.js'
import { Asn1Any, Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the PolicyQualifierInfo structure described in RFC 5035.
 *
 * @asn
 * ```asn
 *
 * CERT-POLICY-QUALIFIER ::= TYPE-IDENTIFIER
 * ERT-POLICY-QUALIFIER ::= TYPE-IDENTIFIER
 *
 * PolicyQualifierInfo ::= SEQUENCE {
 *      policyQualifierId  CERT-POLICY-QUALIFIER.
 *               &id({PolicyQualifierId}),
 *      qualifier          CERT-POLICY-QUALIFIER.
 *               &Type({PolicyQualifierId}{@policyQualifierId})
 * }
 *
 * PolicyQualifierId CERT-POLICY-QUALIFIER ::= { pqid-cps | pqid-unotice, ... }
 * ```
 */
export class PolicyQualifierInfo extends PkiBase<PolicyQualifierInfo> {
    policyQualifierId: ObjectIdentifier
    qualifier: Any

    constructor(options: {
        policyQualifierId: string | ObjectIdentifier
        qualifier: Asn1Any
    }) {
        super()
        this.policyQualifierId = new ObjectIdentifier({
            value: options.policyQualifierId,
        })
        this.qualifier = new Any({ derBytes: options.qualifier })
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [this.policyQualifierId.toAsn1(), this.qualifier.toAsn1()],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PolicyQualifierInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length !== 2) {
            throw new Asn1ParseError(
                'Invalid PolicyQualifierInfo: expected 2 elements',
            )
        }

        const policyQualifierId = ObjectIdentifier.fromAsn1(values[0])
        const qualifier = new Any({ derBytes: values[1] })

        return new PolicyQualifierInfo({ policyQualifierId, qualifier })
    }
}

/**
 * Represents the PolicyInformation structure described in RFC 5035.
 *
 * @asn
 * ```asn
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *          PolicyQualifierInfo OPTIONAL
 * }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 */
export class PolicyInformation extends PkiBase<PolicyInformation> {
    policyIdentifier: ObjectIdentifier
    policyQualifiers?: PolicyQualifierInfo[]

    constructor(options: {
        policyIdentifier: string | ObjectIdentifier
        policyQualifiers?: PolicyQualifierInfo[]
    }) {
        super()
        this.policyIdentifier = new ObjectIdentifier({
            value: options.policyIdentifier,
        })
        this.policyQualifiers = options.policyQualifiers
    }

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = [this.policyIdentifier.toAsn1()]

        if (this.policyQualifiers) {
            values.push(
                new asn1js.Sequence({
                    value: this.policyQualifiers.map((q) => q.toAsn1()),
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PolicyInformation {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const values = asn1.valueBlock.value
        if (values.length < 1 || values.length > 2) {
            throw new Asn1ParseError(
                'Invalid PolicyInformation: expected 1 to 2 elements',
            )
        }

        const policyIdentifier = ObjectIdentifier.fromAsn1(values[0])

        let policyQualifiers: PolicyQualifierInfo[] | undefined
        if (values.length > 1) {
            const qualifiersAsn1 = values[1]
            if (!(qualifiersAsn1 instanceof asn1js.Sequence)) {
                throw new Asn1ParseError(
                    'Invalid PolicyInformation: expected SEQUENCE for policyQualifiers',
                )
            }

            policyQualifiers = qualifiersAsn1.valueBlock.value.map((q) => {
                return PolicyQualifierInfo.fromAsn1(q)
            })
        }

        return new PolicyInformation({ policyIdentifier, policyQualifiers })
    }
}
