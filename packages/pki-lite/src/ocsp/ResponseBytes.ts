import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { OctetString } from '../asn1/OctetString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * ResponseBytes ::= SEQUENCE {
 *     responseType        OBJECT IDENTIFIER,
 *     response            OCTET STRING
 * }
 */
export class ResponseBytes extends PkiBase<ResponseBytes> {
    responseType: string
    response: OctetString

    constructor(options: {
        responseType: string
        response: Uint8Array<ArrayBuffer> | OctetString | string | PkiBase
    }) {
        super()
        this.responseType = options.responseType
        this.response = new OctetString({ bytes: options.response })
    }

    toAsn1(): Asn1BaseBlock {
        return new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: this.responseType }),
                this.response.toAsn1(),
            ],
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): ResponseBytes {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (sequence.valueBlock.value.length !== 2) {
            throw new Asn1ParseError(
                'Invalid ResponseBytes: expected 2 elements',
            )
        }

        const responseTypeBlock = sequence.valueBlock
            .value[0] as asn1js.ObjectIdentifier
        const responseType = responseTypeBlock.valueBlock.toString()
        const response = OctetString.fromAsn1(sequence.valueBlock.value[1])

        return new ResponseBytes({
            responseType,
            response,
        })
    }
}
