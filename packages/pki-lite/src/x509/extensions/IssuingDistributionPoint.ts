import { Asn1Node, der, PkiBase, UniversalTag } from '../../core/PkiBase.js'
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

    static fromAsn1(asn1: Asn1Node): IssuingDistributionPoint {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure for IssuingDistributionPoint',
            )
        }
        // [n] IMPLICIT BOOLEAN: one content octet, non-zero for TRUE
        const flag = (element: Asn1Node) => {
            if (element.constructed || element.content.length !== 1) {
                throw new Asn1ParseError(
                    'Invalid BOOLEAN in IssuingDistributionPoint',
                )
            }
            return element.content[0] !== 0
        }
        const idp = new IssuingDistributionPoint()
        for (const element of asn1.children) {
            if (isContextTag(element, 0)) {
                // [0] EXPLICIT: DistributionPointName is a CHOICE
                idp.distributionPoint = DistributionPointName.fromAsn1(
                    element.items('distributionPoint')[0],
                )
            } else if (isContextTag(element, 1)) {
                idp.onlyContainsUserCerts = flag(element)
            } else if (isContextTag(element, 2)) {
                idp.onlyContainsCACerts = flag(element)
            } else if (isContextTag(element, 3)) {
                // [3] IMPLICIT BIT STRING
                idp.onlySomeReasons = ReasonFlags.fromAsn1(
                    element.retag(UniversalTag.BitString),
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
        // DER: the DEFAULT FALSE flags are left out unless set
        const flag = (set: boolean, tag: number) => {
            if (set) value.push(implicitTag(der.boolean(true), tag))
        }
        flag(this.onlyContainsUserCerts, 1)
        flag(this.onlyContainsCACerts, 2)
        if (this.onlySomeReasons) {
            value.push(implicitTag(this.onlySomeReasons.toAsn1(), 3))
        }
        flag(this.indirectCRL, 4)
        flag(this.onlyContainsAttributeCerts, 5)
        return der.sequence(value)
    }
}
