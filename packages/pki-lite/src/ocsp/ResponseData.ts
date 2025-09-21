import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { Extension } from '../x509/Extension.js'
import { ResponderID } from './ResponderID.js'
import { SingleResponse } from './SingleResponse.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * ResponseData ::= SEQUENCE {
 *     version              [0] EXPLICIT Version DEFAULT v1,
 *     responderID              ResponderID,
 *     producedAt               GeneralizedTime,
 *     responses                SEQUENCE OF SingleResponse,
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL
 * }
 */
export class ResponseData extends PkiBase<ResponseData> {
    version: number
    responderID: ResponderID
    producedAt: Date
    responses: SingleResponse[]
    responseExtensions?: Extension[]

    constructor(options: {
        responses: SingleResponse[]
        responderID: ResponderID
        producedAt: Date
        version?: number // v1
        responseExtensions?: Extension[]
    }) {
        super()
        this.version = options.version ?? 0
        this.responderID = options.responderID
        this.producedAt = options.producedAt
        this.responses = options.responses
        this.responseExtensions = options.responseExtensions
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = []

        // Only include version if it's not the default (v1=0)
        if (this.version !== 0) {
            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [new asn1js.Integer({ value: this.version })],
                }),
            )
        }

        const responderIdAsn1 = ResponderID.toAsn1(this.responderID)

        values.push(
            responderIdAsn1,
            new asn1js.GeneralizedTime({ valueDate: this.producedAt }),
            new asn1js.Sequence({
                value: this.responses.map((resp) => resp.toAsn1()),
            }),
        )

        if (this.responseExtensions && this.responseExtensions.length > 0) {
            const extensions = new asn1js.Sequence({
                value: this.responseExtensions.map((ext) => ext.toAsn1()),
            })

            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 1, // [1]
                    },
                    value: [extensions],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): ResponseData {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        let currentIndex = 0
        let version = 0 // Default is v1 (0)

        // Check for version [0]
        if (
            currentIndex < sequence.valueBlock.value.length &&
            sequence.valueBlock.value[currentIndex] instanceof
                asn1js.Constructed &&
            (sequence.valueBlock.value[currentIndex] as asn1js.Constructed)
                .idBlock.tagNumber === 0
        ) {
            const versionContainer = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            const versionInt = versionContainer.valueBlock
                .value[0] as asn1js.Integer
            version = versionInt.valueBlock.valueDec as number
            currentIndex++
        }

        if (currentIndex >= sequence.valueBlock.value.length) {
            throw new Asn1ParseError(
                'Invalid ResponseData: missing responderID',
            )
        }
        const responderID = ResponderID.fromAsn1(
            sequence.valueBlock.value[currentIndex],
        )
        currentIndex++

        if (currentIndex >= sequence.valueBlock.value.length) {
            throw new Asn1ParseError('Invalid ResponseData: missing producedAt')
        }
        const producedAtBlock = sequence.valueBlock.value[
            currentIndex
        ] as asn1js.GeneralizedTime
        const producedAt = new Date(producedAtBlock.valueBlock.value)
        currentIndex++

        if (currentIndex >= sequence.valueBlock.value.length) {
            throw new Asn1ParseError('Invalid ResponseData: missing responses')
        }
        const responsesSequence = sequence.valueBlock.value[
            currentIndex
        ] as asn1js.Sequence
        const responses = responsesSequence.valueBlock.value.map((resp) =>
            SingleResponse.fromAsn1(resp),
        )
        currentIndex++

        let responseExtensions: Extension[] | undefined = undefined

        // Check for responseExtensions [1]
        if (
            currentIndex < sequence.valueBlock.value.length &&
            sequence.valueBlock.value[currentIndex] instanceof
                asn1js.Constructed &&
            (sequence.valueBlock.value[currentIndex] as asn1js.Constructed)
                .idBlock.tagNumber === 1
        ) {
            const extensionsContainer = sequence.valueBlock.value[
                currentIndex
            ] as asn1js.Constructed
            const extensionsSequence = extensionsContainer.valueBlock
                .value[0] as asn1js.Sequence
            responseExtensions = extensionsSequence.valueBlock.value.map(
                (ext) => Extension.fromAsn1(ext),
            )
        }

        return new ResponseData({
            responses,
            responderID,
            producedAt,
            version,
            responseExtensions,
        })
    }
}
