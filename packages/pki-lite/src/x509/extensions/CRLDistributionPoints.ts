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

        if (asn1.idBlock.tagClass === 3 && asn1.idBlock.tagNumber === 0) {
            return GeneralNames.fromAsn1(asn1.valueBlock.value[0])
        } else if (
            asn1.idBlock.tagClass === 3 &&
            asn1.idBlock.tagNumber === 1
        ) {
            return RelativeDistinguishedName.fromAsn1(asn1.valueBlock.value[0])
        }
        throw new Asn1ParseError('Invalid DistributionPointName choice')
    },
    toAsn1(value: DistributionPointName): Asn1BaseBlock {
        if (value instanceof GeneralNames) {
            return new asn1js.Constructed({
                idBlock: {
                    tagClass: 3,
                    tagNumber: 0,
                },
                value: [value.toAsn1()],
            })
        } else if (value instanceof RelativeDistinguishedName) {
            return new asn1js.Constructed({
                idBlock: {
                    tagClass: 3,
                    tagNumber: 1,
                },
                value: [value.toAsn1()],
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
            value.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3,
                        tagNumber: 0,
                    },
                    value: [
                        DistributionPointName.toAsn1(this.distributionPoint),
                    ],
                }),
            )
        }

        if (this.reasons) {
            value.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3,
                        tagNumber: 1,
                    },
                    value: [this.reasons.toAsn1()],
                }),
            )
        }

        if (this.cRLIssuer) {
            value.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3,
                        tagNumber: 2,
                    },
                    value: [this.cRLIssuer.toAsn1()],
                }),
            )
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
            if (!(element instanceof asn1js.Constructed)) {
                throw new Asn1ParseError(
                    'Invalid DistributionPoint ASN.1 structure. Expected Constructed but got ' +
                        element.constructor.name,
                )
            }

            if (
                element.idBlock.tagClass === 3 &&
                element.idBlock.tagNumber === 0
            ) {
                dp.distributionPoint = DistributionPointName.fromAsn1(
                    element.valueBlock.value[0],
                )
            } else if (
                element.idBlock.tagClass === 3 &&
                element.idBlock.tagNumber === 1
            ) {
                dp.reasons = ReasonFlags.fromAsn1(element.valueBlock.value[0])
            } else if (
                element.idBlock.tagClass === 3 &&
                element.idBlock.tagNumber === 2
            ) {
                dp.cRLIssuer = GeneralNames.fromAsn1(
                    element.valueBlock.value[0],
                )
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
