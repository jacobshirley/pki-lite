import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
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

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [
            new asn1js.GeneralizedTime({
                valueDate: this.revocationTime,
            }),
        ]

        if (this.revocationReason !== undefined) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [this.revocationReason.toAsn1()],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): RevokedInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (
            sequence.valueBlock.value.length < 1 ||
            sequence.valueBlock.value.length > 2
        ) {
            throw new Asn1ParseError(
                'Invalid RevokedInfo: expected 1 or 2 elements',
            )
        }

        const revocationTimeBlock = sequence.valueBlock
            .value[0] as asn1js.GeneralizedTime
        // Use toDate() method for proper date parsing
        const revocationTime = revocationTimeBlock.toDate()

        let revocationReason: number | undefined = undefined

        if (sequence.valueBlock.value.length === 2) {
            const revocationReasonBlock = sequence.valueBlock
                .value[1] as asn1js.Constructed
            if (
                revocationReasonBlock.idBlock.tagClass !== 3 ||
                revocationReasonBlock.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid RevokedInfo: expected [0] tag for revocationReason',
                )
            }

            const reasonValue = revocationReasonBlock.valueBlock
                .value[0] as asn1js.Enumerated
            if (!(reasonValue instanceof asn1js.Enumerated)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure: expected ENUMERATED for revocation reason',
                )
            }
            revocationReason = reasonValue.valueBlock.valueDec
        }

        return new RevokedInfo({ revocationTime, revocationReason })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): RevokedInfo {
        return RevokedInfo.fromAsn1(derToAsn1(der))
    }
}
