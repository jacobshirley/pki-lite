import { Asn1BaseBlock, asn1js, PkiBase } from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../x509/Certificate.js'
import { ResponseData } from './ResponseData.js'
import { BitString } from '../asn1/BitString.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * BasicOCSPResponse ::= SEQUENCE {
 *     tbsResponseData      ResponseData,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signature            BIT STRING,
 *     certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
 * }
 */
export class BasicOCSPResponse extends PkiBase<BasicOCSPResponse> {
    tbsResponseData: ResponseData
    signatureAlgorithm: AlgorithmIdentifier
    signature: BitString
    certs?: Certificate[]

    constructor(options: {
        tbsResponseData: ResponseData
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array | BitString
        certs?: Certificate[]
    }) {
        super()
        this.tbsResponseData = options.tbsResponseData
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signature = new BitString({ value: options.signature })
        this.certs = options.certs
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [
            this.tbsResponseData.toAsn1(),
            this.signatureAlgorithm.toAsn1(),
            this.signature.toAsn1(),
        ]

        if (this.certs && this.certs.length > 0) {
            const certsSequence = new asn1js.Sequence({
                value: this.certs.map((cert) => cert.toAsn1()),
            })

            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [certsSequence],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): BasicOCSPResponse {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (
            sequence.valueBlock.value.length < 3 ||
            sequence.valueBlock.value.length > 4
        ) {
            throw new Asn1ParseError(
                'Invalid BasicOCSPResponse: expected 3 or 4 elements',
            )
        }

        const tbsResponseData = ResponseData.fromAsn1(
            sequence.valueBlock.value[0],
        )
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            sequence.valueBlock.value[1],
        )
        const signatureBlock = sequence.valueBlock.value[2] as asn1js.BitString
        const signature = signatureBlock.valueBlock.valueHexView

        let certs: Certificate[] | undefined = undefined

        if (sequence.valueBlock.value.length > 3) {
            const certsContainer = sequence.valueBlock
                .value[3] as asn1js.Constructed
            if (
                certsContainer.idBlock.tagClass !== 3 ||
                certsContainer.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid BasicOCSPResponse: expected [0] tag for certs',
                )
            }

            const certsSequence = certsContainer.valueBlock
                .value[0] as asn1js.Sequence
            certs = certsSequence.valueBlock.value.map((cert) =>
                Certificate.fromAsn1(cert),
            )
        }

        return new BasicOCSPResponse({
            tbsResponseData,
            signatureAlgorithm,
            signature,
            certs,
        })
    }
}
