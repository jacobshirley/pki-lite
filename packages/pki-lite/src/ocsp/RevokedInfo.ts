import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { CRLReason } from '../x509/CRLReason.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents the information about a revoked certificate.
 *
 * @asn
 * ```asn
 * RevokedInfo ::= SEQUENCE {
 *     revocationTime              GeneralizedTime,
 *     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
 *
 * }
 * ```
 */
export class RevokedInfo extends PkiBase<RevokedInfo> {
    revocationTime: Date
    revocationReason?: CRLReason

    constructor(options: {
        revocationTime: Date
        revocationReason?: number | CRLReason
    }) {
        super()
        this.revocationTime = options.revocationTime
        this.revocationReason =
            options.revocationReason === undefined
                ? undefined
                : options.revocationReason instanceof CRLReason
                  ? options.revocationReason
                  : new CRLReason(options.revocationReason)
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [der.generalizedTime(this.revocationTime)]

        if (this.revocationReason !== undefined) {
            values.push(der.constructed(0, [this.revocationReason.toAsn1()]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): RevokedInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length < 1 || sequence.children.length > 2) {
            throw new Asn1ParseError(
                'Invalid RevokedInfo: expected 1 or 2 elements',
            )
        }

        const revocationTimeBlock = sequence.children[0]
        // Use toDate() method for proper date parsing
        const revocationTime = der.readTime(revocationTimeBlock)

        let revocationReason: number | undefined = undefined

        if (sequence.children.length === 2) {
            const revocationReasonBlock = sequence.children[1]
            if (
                revocationReasonBlock.tagClass !== TagClass.Context ||
                revocationReasonBlock.tag !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid RevokedInfo: expected [0] tag for revocationReason',
                )
            }

            const reasonValue = revocationReasonBlock.children[0]
            if (!reasonValue.is(UniversalTag.Enumerated)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected ENUMERATED for revocation reason',
                )
            }
            revocationReason = der.readEnumerated(reasonValue)
        }

        return new RevokedInfo({ revocationTime, revocationReason })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): RevokedInfo {
        return RevokedInfo.fromAsn1(derToAsn1(der))
    }
}
