import {
    Asn1Node,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * CertStatus ::= CHOICE {
 *     good                [0] IMPLICIT NULL,
 *     revoked             [1] IMPLICIT RevokedInfo,
 *     unknown             [2] IMPLICIT UnknownInfo
 * }
 *
 * UnknownInfo ::= NULL
 */
export class CertStatus extends PkiBase<CertStatus> {
    static readonly good = new CertStatus({ status: 'good' })
    static readonly revoked = new CertStatus({ status: 'revoked' })
    static readonly unknown = new CertStatus({ status: 'unknown' })
    status: 'good' | 'revoked' | 'unknown'
    revocationTime?: Date
    revocationReason?: number

    constructor(options: {
        status: 'good' | 'revoked' | 'unknown'
        revocationTime?: Date
        revocationReason?: number
    }) {
        super()
        this.status = options.status
        this.revocationTime = options.revocationTime
        this.revocationReason = options.revocationReason
    }

    static createGood(): CertStatus {
        return new CertStatus({
            status: 'good',
        })
    }

    static createRevoked(
        revocationTime: Date,
        revocationReason?: number,
    ): CertStatus {
        return new CertStatus({
            status: 'revoked',
            revocationTime,
            revocationReason,
        })
    }

    static createUnknown(): CertStatus {
        return new CertStatus({
            status: 'unknown',
        })
    }

    toAsn1(): Asn1Node {
        if (this.status === 'good') {
            // good [0] IMPLICIT NULL
            return der.nullValue().implicit(0)
        } else if (this.status === 'revoked') {
            const values: Asn1Node[] = [
                der.generalizedTime(this.revocationTime || new Date()),
            ]

            if (this.revocationReason !== undefined) {
                values.push(
                    der.constructed(0, [der.enumerated(this.revocationReason)]),
                )
            }

            // revoked [1] IMPLICIT RevokedInfo: the RevokedInfo fields sit directly
            // inside the [1], there is no SEQUENCE in between.
            return der.constructed(1, values)
        } else {
            // unknown
            // unknown [2] IMPLICIT NULL
            return der.nullValue().implicit(2)
        }
    }

    static fromAsn1(asn1: Asn1Node): CertStatus {
        if (
            !asn1.constructed &&
            asn1.tagClass === TagClass.Context &&
            asn1.tag === 0
        ) {
            // good
            return CertStatus.createGood()
        } else if (
            asn1?.constructed &&
            asn1.tagClass === TagClass.Context &&
            asn1.tag === 1
        ) {
            // revoked
            // The RevokedInfo fields are the children of [1]. Earlier versions of this
            // library wrapped them in an extra SEQUENCE, so accept that too.
            const children = asn1.children
            const [first] = children
            const fields =
                children.length === 1 && first.is(UniversalTag.Sequence)
                    ? first.children
                    : children
            const revocationTimeBlock = fields[0]
            if (!revocationTimeBlock.is(UniversalTag.GeneralizedTime)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure for CertStatus: revocationTime must be a GeneralizedTime',
                )
            }
            const revocationTime = der.readTime(revocationTimeBlock)

            let revocationReason: number | undefined = undefined
            if (fields.length > 1) {
                const reasonContainer = fields[1]
                if (
                    reasonContainer.tagClass === TagClass.Context &&
                    reasonContainer.tag === 0
                ) {
                    const reasonValue = reasonContainer.children[0]
                    revocationReason = der.readEnumerated(reasonValue)
                }
            }

            return CertStatus.createRevoked(revocationTime, revocationReason)
        } else if (
            !asn1.constructed &&
            asn1.tagClass === TagClass.Context &&
            asn1.tag === 2
        ) {
            // unknown
            return CertStatus.createUnknown()
        } else {
            throw new Asn1ParseError('Invalid ASN.1 structure for CertStatus')
        }
    }
}
