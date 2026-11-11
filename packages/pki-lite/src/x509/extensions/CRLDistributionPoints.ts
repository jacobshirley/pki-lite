import {
    Asn1Node,
    Choice,
    der,
    PkiBase,
    PkiSequence,
    UniversalTag,
} from '../../core/PkiBase.js'
import { GeneralNames } from '../GeneralName.js'
import { ReasonFlags } from '../ReasonFlags.js'
import { RelativeDistinguishedName } from '../RelativeDistinguishedName.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag, isContextTag } from '../../core/tagging.js'

/**
 * Represents X.509 DistributionPointName
 *
 * @asn
 * ```asn
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName
 * }
 */
export type DistributionPointName = GeneralNames | RelativeDistinguishedName
export const DistributionPointName = Choice('DistributionPointName', {
    fullName: GeneralNames,
    nameRelativeToCRLIssuer: RelativeDistinguishedName,
    fromAsn1(asn1: Asn1Node): DistributionPointName {
        if (!asn1?.constructed) {
            throw new Asn1ParseError(
                'Invalid DistributionPointName ASN.1 structure. Expected Constructed but got ' +
                    asn1.describe(),
            )
        }

        // Both alternatives are IMPLICIT: the elements sit directly in [0] / [1]
        if (isContextTag(asn1, 0)) {
            return GeneralNames.fromImplicitAsn1(asn1)
        } else if (isContextTag(asn1, 1)) {
            const [first] = asn1.children
            if (asn1.children.length === 1 && first.is(UniversalTag.Set)) {
                // explicit form written by earlier versions
                return RelativeDistinguishedName.fromAsn1(first)
            }
            return RelativeDistinguishedName.fromAsn1(der.set(asn1.children))
        }
        throw new Asn1ParseError('Invalid DistributionPointName choice')
    },
    toAsn1(value: DistributionPointName): Asn1Node {
        if (value instanceof GeneralNames) {
            return value.toImplicitAsn1(0)
        } else if (value instanceof RelativeDistinguishedName) {
            return der.constructed(1, value.toAsn1().children)
        }
        throw new Asn1ParseError('Invalid DistributionPointName choice')
    },
})

/**
 * Represents X.509 DistributionPoint
 *
 * @asn
 * ```asn
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL
 * }
 */
export class DistributionPoint extends PkiBase<DistributionPoint> {
    distributionPoint?: DistributionPointName
    reasons?: ReasonFlags
    cRLIssuer?: GeneralNames

    constructor(options?: {
        distributionPoint?: DistributionPointName
        reasons?: ReasonFlags
        cRLIssuer?: GeneralNames
    }) {
        super()
        this.distributionPoint = options?.distributionPoint
        this.reasons = options?.reasons
        this.cRLIssuer = options?.cRLIssuer
    }

    toAsn1(): Asn1Node {
        const value: Asn1Node[] = []
        if (this.distributionPoint) {
            // DistributionPointName is a CHOICE, so [0] is EXPLICIT here
            value.push(
                der.constructed(0, [
                    DistributionPointName.toAsn1(this.distributionPoint),
                ]),
            )
        }

        if (this.reasons) {
            // reasons [1] IMPLICIT ReasonFlags (BIT STRING)
            value.push(implicitTag(this.reasons.toAsn1(), 1))
        }

        if (this.cRLIssuer) {
            // cRLIssuer [2] IMPLICIT GeneralNames
            value.push(this.cRLIssuer.toImplicitAsn1(2))
        }

        return der.sequence(value)
    }

    static fromAsn1(asn1: Asn1Node): DistributionPoint {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for DistributionPoint',
            )
        }
        const dp = new DistributionPoint()
        for (const element of asn1.children) {
            if (isContextTag(element, 0)) {
                if (!element?.constructed) {
                    throw new Asn1ParseError(
                        'Invalid DistributionPoint ASN.1 structure. Expected Constructed but got ' +
                            element.describe(),
                    )
                }
                dp.distributionPoint = DistributionPointName.fromAsn1(
                    element.children[0],
                )
            } else if (isContextTag(element, 1)) {
                if (element?.constructed) {
                    // explicit form written by earlier versions
                    dp.reasons = ReasonFlags.fromAsn1(element.children[0])
                } else if (element.is(UniversalTag.BitString)) {
                    dp.reasons = ReasonFlags.fromAsn1(element)
                } else {
                    // reasons [1] IMPLICIT BIT STRING: the content is the unused-bits
                    // count followed by the bits
                    dp.reasons = ReasonFlags.fromAsn1(
                        element.retag(UniversalTag.BitString),
                    )
                }
            } else if (isContextTag(element, 2)) {
                dp.cRLIssuer = GeneralNames.fromImplicitAsn1(element)
            } else {
                throw new Asn1ParseError('Invalid tag in DistributionPoint')
            }
        }
        return dp
    }
}

/**
 * Represents X.509 CRLDistributionPoints extension
 *
 * @asn
 * ```asn
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 * ```
 */
export class CRLDistributionPoints extends PkiSequence<DistributionPoint> {
    static DistributionPoint = DistributionPoint

    static fromAsn1(asn1: Asn1Node): CRLDistributionPoints {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for CRLDistributionPoints',
            )
        }
        const points = asn1.children.map(DistributionPoint.fromAsn1)
        return new CRLDistributionPoints(...points)
    }
}
