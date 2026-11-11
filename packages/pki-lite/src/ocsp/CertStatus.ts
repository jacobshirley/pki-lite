import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
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

    toAsn1(): Asn1BaseBlock {
        if (this.status === 'good') {
            return new asn1js.Primitive({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 0, // [0]
                },
                lenBlock: { length: 1 },
            })
        } else if (this.status === 'revoked') {
            const values: asn1js.AsnType[] = [
                new asn1js.GeneralizedTime({
                    valueDate: this.revocationTime || new Date(),
                }),
            ]

            if (this.revocationReason !== undefined) {
                values.push(
                    new asn1js.Constructed({
                        idBlock: {
                            tagClass: 3, // CONTEXT-SPECIFIC
                            tagNumber: 0, // [0]
                        },
                        value: [
                            new asn1js.Enumerated({
                                value: this.revocationReason,
                            }),
                        ],
                    }),
                )
            }

            // revoked [1] IMPLICIT RevokedInfo: the RevokedInfo fields sit directly
            // inside the [1], there is no SEQUENCE in between.
            return new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 1, // [1]
                },
                value: values,
            })
        } else {
            // unknown
            return new asn1js.Primitive({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 2, // [2]
                },
                lenBlock: { length: 1 },
            })
        }
    }

    static fromAsn1(asn1: Asn1BaseBlock): CertStatus {
        if (
            asn1 instanceof asn1js.Primitive &&
            asn1.idBlock.tagClass === 3 &&
            asn1.idBlock.tagNumber === 0
        ) {
            // good
            return CertStatus.createGood()
        } else if (
            asn1 instanceof asn1js.Constructed &&
            asn1.idBlock.tagClass === 3 &&
            asn1.idBlock.tagNumber === 1
        ) {
            // revoked
            // The RevokedInfo fields are the children of [1]. Earlier versions of this
            // library wrapped them in an extra SEQUENCE, so accept that too.
            const children = asn1.valueBlock.value
            const [first] = children
            const fields =
                children.length === 1 && first instanceof asn1js.Sequence
                    ? first.valueBlock.value
                    : children
            const revocationTimeBlock = fields[0]
            if (!(revocationTimeBlock instanceof asn1js.GeneralizedTime)) {
                throw new Asn1ParseError(
                    'Invalid ASN.1 structure for CertStatus: revocationTime must be a GeneralizedTime',
                )
            }
            const revocationTime = revocationTimeBlock.toDate()

            let revocationReason: number | undefined = undefined
            if (fields.length > 1) {
                const reasonContainer = fields[1] as asn1js.Constructed
                if (
                    reasonContainer.idBlock.tagClass === 3 &&
                    reasonContainer.idBlock.tagNumber === 0
                ) {
                    const reasonValue = reasonContainer.valueBlock
                        .value[0] as asn1js.Enumerated
                    revocationReason = reasonValue.valueBlock.valueDec
                }
            }

            return CertStatus.createRevoked(revocationTime, revocationReason)
        } else if (
            asn1 instanceof asn1js.Primitive &&
            asn1.idBlock.tagClass === 3 &&
            asn1.idBlock.tagNumber === 2
        ) {
            // unknown
            return CertStatus.createUnknown()
        } else {
            throw new Asn1ParseError('Invalid ASN.1 structure for CertStatus')
        }
    }
}
