import {
    Asn1Node,
    der,
    derToAsn1,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../core/PkiBase.js'
import { AlgorithmIdentifier } from '../algorithms/AlgorithmIdentifier.js'
import { Certificate } from '../x509/Certificate.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Signature ::= SEQUENCE {
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signature            BIT STRING,
 *     certs             [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
 * }
 */
export class OCSPSignature extends PkiBase<OCSPSignature> {
    signatureAlgorithm: AlgorithmIdentifier
    signature: Uint8Array<ArrayBuffer>
    certs?: Certificate[]

    constructor(options: {
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array
        certs?: Certificate[]
    }) {
        super()
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signature = new Uint8Array(options.signature)
        this.certs = options.certs
    }

    toAsn1(): Asn1Node {
        const values: Asn1Node[] = [
            this.signatureAlgorithm.toAsn1(),
            der.bitString(this.signature),
        ]

        if (this.certs && this.certs.length > 0) {
            const certsSequence = der.sequence(
                this.certs.map((cert) => cert.toAsn1()),
            )

            values.push(der.constructed(0, [certsSequence]))
        }

        return der.sequence(values)
    }

    static fromAsn1(asn1: Asn1Node): OCSPSignature {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1
        if (sequence.children.length < 2 || sequence.children.length > 3) {
            throw new Asn1ParseError(
                'Invalid Signature: expected 2 or 3 elements',
            )
        }

        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            sequence.children[0],
        )

        const signatureBlock = sequence.children[1]
        const signature = der.readBitString(signatureBlock).bytes

        let certs: Certificate[] | undefined = undefined

        if (sequence.children.length === 3) {
            const certsContainer = sequence.children[2]
            if (
                certsContainer.tagClass !== TagClass.Context ||
                certsContainer.tag !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid Signature: expected [0] tag for certs',
                )
            }

            const certsSequence = certsContainer.children[0]
            certs = certsSequence.children.map((cert) =>
                Certificate.fromAsn1(cert),
            )
        }

        return new OCSPSignature({
            signatureAlgorithm,
            signature,
            certs,
        })
    }

    static fromDer(der: Uint8Array<ArrayBuffer>): OCSPSignature {
        return OCSPSignature.fromAsn1(derToAsn1(der))
    }
}
