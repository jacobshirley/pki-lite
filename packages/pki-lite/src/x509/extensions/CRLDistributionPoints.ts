import {
    Asn1BaseBlock,
    asn1js,
    Choice,
    PkiBase,
    PkiSequence,
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
    fromAsn1(asn1: Asn1BaseBlock): DistributionPointName {
        if (!(asn1 instanceof asn1js.Constructed)) {
            throw new Asn1ParseError(
                'Invalid DistributionPointName ASN.1 structure. Expected Constructed but got ' +
                    asn1.constructor.name,
            )
        }

        // Both alternatives are IMPLICIT: the elements sit directly in [0] / [1]
        if (isContextTag(asn1, 0)) {
            return GeneralNames.fromImplicitAsn1(asn1)
        } else if (isContextTag(asn1, 1)) {
            const [first] = asn1.valueBlock.value
            if (
                asn1.valueBlock.value.length === 1 &&
                first instanceof asn1js.Set
            ) {
                // explicit form written by earlier versions
                return RelativeDistinguishedName.fromAsn1(first)
            }
            return RelativeDistinguishedName.fromAsn1(
                new asn1js.Set({ value: asn1.valueBlock.value }),
            )
        }
        throw new Asn1ParseError('Invalid DistributionPointName choice')
    },
    toAsn1(value: DistributionPointName): Asn1BaseBlock {
        if (value instanceof GeneralNames) {
            return value.toImplicitAsn1(0)
        } else if (value instanceof RelativeDistinguishedName) {
            return new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: (value.toAsn1() as asn1js.Set).valueBlock.value,
            })
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

    toAsn1(): Asn1BaseBlock {
        const value: Asn1BaseBlock[] = []
        if (this.distributionPoint) {
            // DistributionPointName is a CHOICE, so [0] is EXPLICIT here
            value.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [
                        DistributionPointName.toAsn1(this.distributionPoint),
                    ],
                }),
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

        return new asn1js.Sequence({ value })
    }

    static fromAsn1(asn1: Asn1BaseBlock): DistributionPoint {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for DistributionPoint',
            )
        }
        const dp = new DistributionPoint()
        for (const element of asn1.valueBlock.value) {
            if (isContextTag(element, 0)) {
                if (!(element instanceof asn1js.Constructed)) {
                    throw new Asn1ParseError(
                        'Invalid DistributionPoint ASN.1 structure. Expected Constructed but got ' +
                            element.constructor.name,
                    )
                }
                dp.distributionPoint = DistributionPointName.fromAsn1(
                    element.valueBlock.value[0],
                )
            } else if (isContextTag(element, 1)) {
                if (element instanceof asn1js.Constructed) {
                    // explicit form written by earlier versions
                    dp.reasons = ReasonFlags.fromAsn1(
                        element.valueBlock.value[0],
                    )
                } else if (element instanceof asn1js.BitString) {
                    dp.reasons = ReasonFlags.fromAsn1(element)
                } else {
                    // reasons [1] IMPLICIT BIT STRING: the content is the unused-bits
                    // count followed by the bits
                    const content = (element as asn1js.Primitive).valueBlock
                        .valueHexView
                    dp.reasons = ReasonFlags.fromAsn1(
                        new asn1js.BitString({
                            valueHex: content.slice(1),
                            unusedBits: content[0],
                        }),
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

    static fromAsn1(asn1: Asn1BaseBlock): CRLDistributionPoints {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for CRLDistributionPoints',
            )
        }
        const points = asn1.valueBlock.value.map(DistributionPoint.fromAsn1)
        return new CRLDistributionPoints(...points)
    }
}
