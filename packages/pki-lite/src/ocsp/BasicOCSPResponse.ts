import {
    Asn1Node,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
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
        signature: Uint8Array<ArrayBuffer> | BitString
        certs?: Certificate[]
    }) {
        super()
        this.tbsResponseData = options.tbsResponseData
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signature = new BitString({ value: options.signature })
        this.certs = options.certs
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [
            this.tbsResponseData.toAsn1(),
            this.signatureAlgorithm.toAsn1(),
            this.signature.toAsn1(),
        ]

        if (this.certs && this.certs.length > 0) {
            const certsSequence = der.sequence(
                this.certs.map((cert) => cert.toAsn1()),
            )

            values.push(der.constructed(0, [certsSequence]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): BasicOCSPResponse {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length < 3 || sequence.children.length > 4) {
            throw new Asn1ParseError(
                'Invalid BasicOCSPResponse: expected 3 or 4 elements',
            )
        }

        const tbsResponseData = ResponseData.fromAsn1(sequence.children[0])
        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            sequence.children[1],
        )
        const signatureBlock = sequence.children[2]
        const signature = der.readBitString(signatureBlock).bytes

        let certs: Certificate[] | undefined = undefined

        if (sequence.children.length > 3) {
            const certsContainer = sequence.children[3]
            if (
                certsContainer.tagClass !== TagClass.Context ||
                certsContainer.tag !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid BasicOCSPResponse: expected [0] tag for certs',
                )
            }

            const certsSequence = certsContainer.children[0]
            certs = certsSequence.children.map((cert) =>
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
