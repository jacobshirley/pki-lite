import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
import { Extension } from '../x509/Extension.js'
import { CertID } from './CertID.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Request ::= SEQUENCE {
 *     reqCert                  CertID,
 *     singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL
 * }
 */
export class Request extends PkiBase<Request> {
    reqCert: CertID
    singleRequestExtensions?: Extension[]

    constructor(options: {
        reqCert: CertID
        singleRequestExtensions?: Extension[]
    }) {
        super()
        this.reqCert = options.reqCert
        this.singleRequestExtensions = options.singleRequestExtensions
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [this.reqCert.toAsn1()]

        if (
            this.singleRequestExtensions &&
            this.singleRequestExtensions.length > 0
        ) {
            const extensions = new asn1js.Sequence({
                value: this.singleRequestExtensions.map((ext) => ext.toAsn1()),
            })

            values.push(
                new asn1js.Constructed({
                    idBlock: {
                        tagClass: 3, // CONTEXT-SPECIFIC
                        tagNumber: 0, // [0]
                    },
                    value: [extensions],
                }),
            )
        }

        return new asn1js.Sequence({
            value: values,
        })
    }

    static fromAsn1(asn1: Asn1BaseBlock): Request {
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
                'Invalid Request: expected 1 or 2 elements',
            )
        }

        const reqCert = CertID.fromAsn1(sequence.valueBlock.value[0])
        let singleRequestExtensions: Extension[] | undefined = undefined

        if (sequence.valueBlock.value.length === 2) {
            const extensionsContainer = sequence.valueBlock
                .value[1] as asn1js.Constructed
            if (
                extensionsContainer.idBlock.tagClass !== 3 ||
                extensionsContainer.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid Request: expected [0] tag for singleRequestExtensions',
                )
            }

            const extensionsSequence = extensionsContainer.valueBlock
                .value[0] as asn1js.Sequence
            singleRequestExtensions = extensionsSequence.valueBlock.value.map(
                (ext) => Extension.fromAsn1(ext),
            )
        }

        return new Request({ reqCert, singleRequestExtensions })
    }

    static fromDer(der: Uint8Array): Request {
        return Request.fromAsn1(derToAsn1(der))
    }
}
