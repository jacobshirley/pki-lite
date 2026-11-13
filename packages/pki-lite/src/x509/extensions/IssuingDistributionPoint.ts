import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag, isContextTag } from '../../core/tagging.js'
import { ReasonFlags } from '../ReasonFlags.js'
import { DistributionPointName } from './CRLDistributionPoints.js'

/**
 * The issuingDistributionPoint CRL extension: which certificates and revocation reasons
 * a CRL covers, and whether it is an indirect CRL.
 *
 * @asn
 * ```asn
 * IssuingDistributionPoint ::= SEQUENCE {
 *      distributionPoint          [0] DistributionPointName OPTIONAL,
 *      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
 *      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
 *      onlySomeReasons            [3] ReasonFlags OPTIONAL,
 *      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
 *      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
 * ```
 */
export class IssuingDistributionPoint extends PkiBase<IssuingDistributionPoint> {
    distributionPoint?: DistributionPointName
    onlyContainsUserCerts: boolean
    onlyContainsCACerts: boolean
    onlySomeReasons?: ReasonFlags
    indirectCRL: boolean
    onlyContainsAttributeCerts: boolean

    constructor(
        options: {
            distributionPoint?: DistributionPointName
            onlyContainsUserCerts?: boolean
            onlyContainsCACerts?: boolean
            onlySomeReasons?: ReasonFlags
            indirectCRL?: boolean
            onlyContainsAttributeCerts?: boolean
        } = {},
    ) {
        super()
        this.distributionPoint = options.distributionPoint
        this.onlyContainsUserCerts = options.onlyContainsUserCerts ?? false
        this.onlyContainsCACerts = options.onlyContainsCACerts ?? false
        this.onlySomeReasons = options.onlySomeReasons
        this.indirectCRL = options.indirectCRL ?? false
        this.onlyContainsAttributeCerts =
            options.onlyContainsAttributeCerts ?? false
    }

    static fromAsn1(asn1: Asn1BaseBlock): IssuingDistributionPoint {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for IssuingDistributionPoint',
            )
        }
        const flag = (element: asn1js.BaseBlock) => {
            // [n] IMPLICIT BOOLEAN: one content octet, non-zero for TRUE
            const content = (element as asn1js.Primitive).valueBlock
                .valueHexView
            if (element.idBlock.isConstructed || content.length !== 1) {
                throw new Asn1ParseError(
                    'Invalid BOOLEAN in IssuingDistributionPoint',
                )
            }
            return content[0] !== 0
        }
        const idp = new IssuingDistributionPoint()
        for (const element of asn1.valueBlock.value) {
            if (isContextTag(element, 0)) {
                // [0] EXPLICIT: DistributionPointName is a CHOICE
                const inner = (element as asn1js.Constructed).valueBlock
                    .value[0]
                idp.distributionPoint = DistributionPointName.fromAsn1(inner)
            } else if (isContextTag(element, 1)) {
                idp.onlyContainsUserCerts = flag(element)
            } else if (isContextTag(element, 2)) {
                idp.onlyContainsCACerts = flag(element)
            } else if (isContextTag(element, 3)) {
                // [3] IMPLICIT BIT STRING: the unused-bits count, then the bits
                const content = (element as asn1js.Primitive).valueBlock
                    .valueHexView
                idp.onlySomeReasons = ReasonFlags.fromAsn1(
                    new asn1js.BitString({
                        valueHex: content.slice(1),
                        unusedBits: content[0],
                    }),
                )
            } else if (isContextTag(element, 4)) {
                idp.indirectCRL = flag(element)
            } else if (isContextTag(element, 5)) {
                idp.onlyContainsAttributeCerts = flag(element)
            } else {
                throw new Asn1ParseError(
                    'Invalid tag in IssuingDistributionPoint',
                )
            }
        }
        return idp
    }

    toAsn1(): Asn1BaseBlock {
        const value: asn1js.BaseBlock[] = []
        if (this.distributionPoint) {
            value.push(
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [
                        DistributionPointName.toAsn1(this.distributionPoint),
                    ],
                }),
            )
        }
        // DER: the DEFAULT FALSE flags are left out unless set
        const flag = (set: boolean, tag: number) => {
            if (set)
                value.push(
                    implicitTag(new asn1js.Boolean({ value: true }), tag),
                )
        }
        flag(this.onlyContainsUserCerts, 1)
        flag(this.onlyContainsCACerts, 2)
        if (this.onlySomeReasons) {
            value.push(implicitTag(this.onlySomeReasons.toAsn1(), 3))
        }
        flag(this.indirectCRL, 4)
        flag(this.onlyContainsAttributeCerts, 5)
        return new asn1js.Sequence({ value })
    }
}
