import { GeneralizedTime } from '../asn1/GeneralizedTime.js'
import {
    Asn1Node,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [
            this.certID.toAsn1(),
            this.certStatus.toAsn1(),
            this.thisUpdate.toAsn1(),
        ]

        if (this.nextUpdate) {
            values.push(der.constructed(0, [this.nextUpdate.toAsn1()]))
        }

        if (this.singleExtensions && this.singleExtensions.length > 0) {
            values.push(
                der.constructed(1, [
                    der.sequence(
                        this.singleExtensions.map((ext) => ext.toAsn1()),
                    ),
                ]),
            )
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): SingleResponse {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length < 3) {
            throw new Asn1ParseError(
                'Invalid SingleResponse: expected at least 3 elements',
            )
        }

        const certID = CertID.fromAsn1(sequence.children[0])
        const certStatus = CertStatus.fromAsn1(sequence.children[1])
        const thisUpdateBlock = sequence.children[2]
        const thisUpdate = der.readTime(thisUpdateBlock)

        let nextUpdate: Date | undefined = undefined
        let singleExtensions: Extension[] | undefined = undefined

        let currentIndex = 3
        while (currentIndex < sequence.children.length) {
            const block = sequence.children[currentIndex]
            if (
                block.tagClass === TagClass.Context &&
                block.tag === 0 &&
                !nextUpdate
            ) {
                // nextUpdate
                const nextUpdateBlock = block.children[0]
                nextUpdate = der.readTime(nextUpdateBlock)
            } else if (
                block.tagClass === TagClass.Context &&
                block.tag === 1 &&
                !singleExtensions
            ) {
                // singleExtensions
                const extensionsSequence = block.children[0]
                singleExtensions = extensionsSequence.children.map((ext) =>
                    Extension.fromAsn1(ext),
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
