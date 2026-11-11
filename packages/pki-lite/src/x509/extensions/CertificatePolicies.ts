import { Asn1BaseBlock, asn1js, PkiSequence } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { PolicyInformation } from '../PolicyInformation.js'

/**
 * Represents the X.509 certificatePolicies extension (RFC 5280 4.2.1.4).
 *
 * @asn
 * ```asn
 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 * ```
 */
export class CertificatePolicies extends PkiSequence<PolicyInformation> {
    /** The policy identifiers (OIDs), in order */
    get policyIdentifiers(): string[] {
        return this.map((policy) => policy.policyIdentifier.value)
    }

    static fromAsn1(asn1: Asn1BaseBlock): CertificatePolicies {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for CertificatePolicies',
            )
        }
        return new CertificatePolicies(
            ...asn1.valueBlock.value.map((policy) =>
                PolicyInformation.fromAsn1(policy),
            ),
        )
    }
}
