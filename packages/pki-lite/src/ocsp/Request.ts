import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
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

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [this.reqCert.toAsn1()]

        if (
            this.singleRequestExtensions &&
            this.singleRequestExtensions.length > 0
        ) {
            const extensions = der.sequence(
                this.singleRequestExtensions.map((ext) => ext.toAsn1()),
            )

            values.push(der.constructed(0, [extensions]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): Request {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length < 1 || sequence.children.length > 2) {
            throw new Asn1ParseError(
                'Invalid Request: expected 1 or 2 elements',
            )
        }

        const reqCert = CertID.fromAsn1(sequence.children[0])
        let singleRequestExtensions: Extension[] | undefined = undefined

        if (sequence.children.length === 2) {
            const extensionsContainer = sequence.children[1]
            if (
                extensionsContainer.tagClass !== TagClass.Context ||
                extensionsContainer.tag !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid Request: expected [0] tag for singleRequestExtensions',
                )
            }

            const extensionsSequence = extensionsContainer.children[0]
            singleRequestExtensions = extensionsSequence.children.map((ext) =>
                Extension.fromAsn1(ext),
            )
        }

        return new Request({ reqCert, singleRequestExtensions })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): Request {
        return Request.fromAsn1(derToAsn1(der))
    }
}
