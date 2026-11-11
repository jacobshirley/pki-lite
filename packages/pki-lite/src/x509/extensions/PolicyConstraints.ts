import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag, isContextTag } from '../../core/tagging.js'

/**
 * Represents the X.509 policyConstraints extension (RFC 5280 4.2.1.11).
 *
 * @asn
 * ```asn
 * PolicyConstraints ::= SEQUENCE {
 *      requireExplicitPolicy   [0] SkipCerts OPTIONAL,
 *      inhibitPolicyMapping    [1] SkipCerts OPTIONAL
 * }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * ```
 */
export class PolicyConstraints extends PkiBase<PolicyConstraints> {
    /** Number of further certificates after which an acceptable policy is required */
    requireExplicitPolicy?: number
    /** Number of further certificates after which policy mapping is no longer allowed */
    inhibitPolicyMapping?: number

    constructor(
        options: {
            requireExplicitPolicy?: number
            inhibitPolicyMapping?: number
        } = {},
    ) {
        super()
        this.requireExplicitPolicy = options.requireExplicitPolicy
        this.inhibitPolicyMapping = options.inhibitPolicyMapping
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []
        // both fields are IMPLICIT INTEGERs
        if (this.requireExplicitPolicy !== undefined) {
            values.push(implicitTag(der.integer(this.requireExplicitPolicy), 0))
        }
        if (this.inhibitPolicyMapping !== undefined) {
            values.push(implicitTag(der.integer(this.inhibitPolicyMapping), 1))
        }
        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): PolicyConstraints {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for PolicyConstraints',
            )
        }

        const skipCerts = (element: Asn1Node): number => {
            const integer = element.is(UniversalTag.Integer)
                ? element
                : element.retag(UniversalTag.Integer)
            return der.readNumber(integer)
        }

        let requireExplicitPolicy: number | undefined
        let inhibitPolicyMapping: number | undefined
        for (const element of asn1.children) {
            if (isContextTag(element, 0)) {
                requireExplicitPolicy = skipCerts(element)
            } else if (isContextTag(element, 1)) {
                inhibitPolicyMapping = skipCerts(element)
            } else {
                throw new Asn1ParseError(
                    'Invalid PolicyConstraints: unexpected element',
                )
            }
        }
        return new PolicyConstraints({
            requireExplicitPolicy,
            inhibitPolicyMapping,
        })
    }
}
