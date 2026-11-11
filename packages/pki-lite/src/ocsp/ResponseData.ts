import { Asn1Node, der, PkiBase, UniversalTag } from '../core/PkiBase.js'
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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        // Only include version if it's not the default (v1=0)
        if (this.version !== 0) {
            values.push(der.constructed(0, [der.integer(this.version)]))
        }

        const responderIdAsn1 = ResponderID.toAsn1(this.responderID)

        values.push(
            responderIdAsn1,
            der.generalizedTime(this.producedAt),
            der.sequence(this.responses.map((resp) => resp.toAsn1())),
        )

        if (this.responseExtensions && this.responseExtensions.length > 0) {
            const extensions = der.sequence(
                this.responseExtensions.map((ext) => ext.toAsn1()),
            )

            values.push(der.constructed(1, [extensions]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): ResponseData {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        let currentIndex = 0
        let version = 0 // Default is v1 (0)

        // Check for version [0]
        if (
            currentIndex < sequence.children.length &&
            sequence.children[currentIndex]?.constructed &&
            sequence.children[currentIndex].tag === 0
        ) {
            const versionContainer = sequence.children[currentIndex]
            const versionInt = versionContainer.children[0]
            version = der.readNumber(versionInt) as number
            currentIndex++
        }

        if (currentIndex >= sequence.children.length) {
            throw new Asn1ParseError(
                'Invalid ResponseData: missing responderID',
            )
        }
        const responderID = ResponderID.fromAsn1(
            sequence.children[currentIndex],
        )
        currentIndex++

        if (currentIndex >= sequence.children.length) {
            throw new Asn1ParseError('Invalid ResponseData: missing producedAt')
        }
        const producedAtBlock = sequence.children[currentIndex]
        const producedAt = der.readTime(producedAtBlock)
        currentIndex++

        if (currentIndex >= sequence.children.length) {
            throw new Asn1ParseError('Invalid ResponseData: missing responses')
        }
        const responsesSequence = sequence.children[currentIndex]
        const responses = responsesSequence.children.map((resp) =>
            SingleResponse.fromAsn1(resp),
        )
        currentIndex++

        let responseExtensions: Extension[] | undefined = undefined

        // Check for responseExtensions [1]
        if (
            currentIndex < sequence.children.length &&
            sequence.children[currentIndex]?.constructed &&
            sequence.children[currentIndex].tag === 1
        ) {
            const extensionsContainer = sequence.children[currentIndex]
            const extensionsSequence = extensionsContainer.children[0]
            responseExtensions = extensionsSequence.children.map((ext) =>
                Extension.fromAsn1(ext),
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
