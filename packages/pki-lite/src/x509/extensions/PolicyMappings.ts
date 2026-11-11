import { ObjectIdentifier } from '../../asn1/ObjectIdentifier.js'
import {
    Asn1Node,
    der,
    ObjectIdentifierString,
    PkiBase,
    PkiSequence,
    UniversalTag,
} from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * One mapping of a policyMappings extension: the issuing CA considers its
 * `issuerDomainPolicy` equivalent to the `subjectDomainPolicy` of the subject CA.
 *
 * @asn
 * ```asn
 * SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId
 * }
 * ```
 */
export class PolicyMapping extends PkiBase<PolicyMapping> {
    issuerDomainPolicy: ObjectIdentifier
    subjectDomainPolicy: ObjectIdentifier

    constructor(options: {
        issuerDomainPolicy: ObjectIdentifierString | ObjectIdentifier
        subjectDomainPolicy: ObjectIdentifierString | ObjectIdentifier
    }) {
        super()
        this.issuerDomainPolicy = new ObjectIdentifier({
            value: options.issuerDomainPolicy,
        })
        this.subjectDomainPolicy = new ObjectIdentifier({
            value: options.subjectDomainPolicy,
        })
    }

    toAsn1(): Asn1Node {
        return der.sequence([
            this.issuerDomainPolicy.toAsn1(),
            this.subjectDomainPolicy.toAsn1(),
        ])
    }

    static fromAsn1(asn1: Asn1Node): PolicyMapping {
        if (!asn1.is(UniversalTag.Sequence) || asn1.children.length !== 2) {
            throw new Asn1ParseError(
                'Invalid PolicyMapping: expected a SEQUENCE of two policy identifiers',
            )
        }
        const [issuer, subject] = asn1.children
        return new PolicyMapping({
            issuerDomainPolicy: ObjectIdentifier.fromAsn1(issuer),
            subjectDomainPolicy: ObjectIdentifier.fromAsn1(subject),
        })
    }
}

/**
 * Represents the X.509 policyMappings extension (RFC 5280 4.2.1.5).
 *
 * @asn
 * ```asn
 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId
 * }
 * ```
 */
export class PolicyMappings extends PkiSequence<PolicyMapping> {
    static PolicyMapping = PolicyMapping

    static fromAsn1(asn1: Asn1Node): PolicyMappings {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for PolicyMappings',
            )
        }
        return new PolicyMappings(
            ...asn1.children.map((mapping) => PolicyMapping.fromAsn1(mapping)),
        )
    }
}
