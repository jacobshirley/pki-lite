import { Asn1BaseBlock, asn1js, PkiBase, derToAsn1 } from '../core/PkiBase.js'
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
    signature: Uint8Array
    certs?: Certificate[]

    constructor(options: {
        signatureAlgorithm: AlgorithmIdentifier
        signature: Uint8Array
        certs?: Certificate[]
    }) {
        super()
        this.signatureAlgorithm = options.signatureAlgorithm
        this.signature = options.signature
        this.certs = options.certs
    }

    toAsn1(): Asn1BaseBlock {
        const values: asn1js.AsnType[] = [
            this.signatureAlgorithm.toAsn1(),
            new asn1js.BitString({ valueHex: this.signature }),
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

    static fromAsn1(asn1: Asn1BaseBlock): OCSPSignature {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE',
            )
        }

        const sequence = asn1 as asn1js.Sequence
        if (
            sequence.valueBlock.value.length < 2 ||
            sequence.valueBlock.value.length > 3
        ) {
            throw new Asn1ParseError(
                'Invalid Signature: expected 2 or 3 elements',
            )
        }

        const signatureAlgorithm = AlgorithmIdentifier.fromAsn1(
            sequence.valueBlock.value[0],
        )

        const signatureBlock = sequence.valueBlock.value[1] as asn1js.BitString
        const signature = signatureBlock.valueBlock.valueHexView

        let certs: Certificate[] | undefined = undefined

        if (sequence.valueBlock.value.length === 3) {
            const certsContainer = sequence.valueBlock
                .value[2] as asn1js.Constructed
            if (
                certsContainer.idBlock.tagClass !== 3 ||
                certsContainer.idBlock.tagNumber !== 0
            ) {
                throw new Asn1ParseError(
                    'Invalid Signature: expected [0] tag for certs',
                )
            }

            const certsSequence = certsContainer.valueBlock
                .value[0] as asn1js.Sequence
            certs = certsSequence.valueBlock.value.map((cert) =>
                Certificate.fromAsn1(cert),
            )
        }

        return new OCSPSignature({
            signatureAlgorithm,
            signature,
            certs,
        })
    }

    static fromDer(der: Uint8Array): OCSPSignature {
        return OCSPSignature.fromAsn1(derToAsn1(der))
    }
}
