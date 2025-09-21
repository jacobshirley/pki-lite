import { GeneralizedTime } from '../asn1/GeneralizedTime.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Extension } from '../x509/Extension.js'
import { CertID } from './CertID.js'
import { CertStatus } from './CertStatus.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * SingleResponse ::= SEQUENCE {
 *     certID                       CertID,
 *     certStatus                   CertStatus,
 *     thisUpdate                   GeneralizedTime,
 *     nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
 *     singleExtensions     [1]     EXPLICIT Extensions OPTIONAL
 * }
 */
export class SingleResponse extends PkiBase<SingleResponse> {
    certID: CertID
    certStatus: CertStatus
    thisUpdate: GeneralizedTime
    nextUpdate?: GeneralizedTime
    singleExtensions?: Extension[]

    constructor(options: {
        certID: CertID
        certStatus: CertStatus
        thisUpdate: Date
        nextUpdate?: Date
        singleExtensions?: Extension[]
    }) {
        super()
        this.certID = options.certID
        this.certStatus = options.certStatus
        this.thisUpdate = new GeneralizedTime({ time: options.thisUpdate })
        this.nextUpdate = options.nextUpdate
            ? new GeneralizedTime({ time: options.nextUpdate })
            : undefined
        this.singleExtensions = options.singleExtensions
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [
            this.certID.toAsn1(),
            this.certStatus.toAsn1(),
            this.thisUpdate.toAsn1(),
        ]

        if (this.nextUpdate) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [this.nextUpdate.toAsn1()],
                }),
            )
        }

        if (this.singleExtensions && this.singleExtensions.length > 0) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    value: [
                        new asn1js.Sequence({
                            value: this.singleExtensions.map((ext) =>
                                ext.toAsn1(),
                            ),
                        }),
                    ],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): SingleResponse {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (sequence.valueBlock.value.length < 3) {
            throw new Asn1ParseError(
                'Invalid SingleResponse: expected at least 3 elements',
            )
        }

        const certID = CertID.fromAsn1(sequence.valueBlock.value[0])
        const certStatus = CertStatus.fromAsn1(sequence.valueBlock.value[1])
        const thisUpdateBlock = sequence.valueBlock
            .value[2] as asn1js.GeneralizedTime
        const thisUpdate = new Date(thisUpdateBlock.valueBlock.value)

        let nextUpdate: Date | undefined = undefined
        let singleExtensions: Extension[] | undefined = undefined

        let currentIndex = 3
        while (currentIndex < sequence.valueBlock.value.length) {
            const block = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            if (
                block.idBlock.tagClass === 3 &&
                block.idBlock.tagNumber === 0 &&
                !nextUpdate
            ) {
                // nextUpdate
                const nextUpdateBlock = block.valueBlock
                    .value[0] as asn1js.GeneralizedTime
                nextUpdate = new Date(nextUpdateBlock.valueBlock.value)
            } else if (
                block.idBlock.tagClass === 3 &&
                block.idBlock.tagNumber === 1 &&
                !singleExtensions
            ) {
                // singleExtensions
                const extensionsSequence = block.valueBlock
                    .value[0] as asn1js.Sequence
                singleExtensions = extensionsSequence.valueBlock.value.map(
                    (ext) => Extension.fromAsn1(ext),
                )
            }
            currentIndex++
        }

        return new SingleResponse({
            certID,
            certStatus,
            thisUpdate,
            nextUpdate,
            singleExtensions,
        })
    }
}
