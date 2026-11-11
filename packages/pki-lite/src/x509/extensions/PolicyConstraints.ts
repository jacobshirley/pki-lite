import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
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

    toAsn1(): Asn1BaseBlock {
        const values: Asn1BaseBlock[] = []
        // both fields are IMPLICIT INTEGERs
        if (this.requireExplicitPolicy !== undefined) {
            values.push(
                implicitTag(
                    new asn1js.Integer({ value: this.requireExplicitPolicy }),
                    0,
                ),
            )
        }
        if (this.inhibitPolicyMapping !== undefined) {
            values.push(
                implicitTag(
                    new asn1js.Integer({ value: this.inhibitPolicyMapping }),
                    1,
                ),
            )
        }
        return new asn1js.Sequence({ value: values })
    }

    static fromAsn1(asn1: Asn1BaseBlock): PolicyConstraints {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for PolicyConstraints',
            )
        }

        const skipCerts = (element: Asn1BaseBlock): number => {
            const integer =
                element instanceof asn1js.Integer
                    ? element
                    : new asn1js.Integer({
                          valueHex: (element as asn1js.Primitive).valueBlock
                              .valueHexView,
                      })
            return integer.valueBlock.valueDec
        }

        let requireExplicitPolicy: number | undefined
        let inhibitPolicyMapping: number | undefined
        for (const element of asn1.valueBlock.value) {
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
