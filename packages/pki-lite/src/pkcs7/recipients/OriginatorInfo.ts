import { CertificateSet } from '../../x509/CertificateSet.js'
import { Asn1BaseBlock, asn1js, PkiBase } from '../../core/PkiBase.js'
import { RevocationInfoChoices } from '../../revocation/RevocationInfoChoices.js'
import { RevocationInfoChoice } from '../../revocation/RevocationInfoChoice.js'
import { CertificateChoices } from '../../x509/CertificateChoices.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an OriginatorInfo structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * OriginatorInfo ::= SEQUENCE {
 *   certs [0] IMPLICIT CertificateSet OPTIONAL,
 *   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
 * }
 * ```
 */
export class OriginatorInfo extends PkiBase<OriginatorInfo> {
    certs?: CertificateSet
    crls?: RevocationInfoChoices

    /**
     * Creates a new OriginatorInfo instance.
     */
    constructor(
        options: {
            certs?: CertificateChoices[]
            crls?: RevocationInfoChoice[]
        } = {},
    ) {
        super()
        const { certs, crls } = options
        this.certs = certs?.length ? new CertificateSet(...certs) : undefined
        this.crls = crls?.length
            ? new RevocationInfoChoices(...crls)
            : undefined
    }

    /**
     * Converts the OriginatorInfo to an ASN.1 structure.
     */
    toAsn1(): Asn1BaseBlock {
        const sequence = new asn1js.Sequence()

        // Add certs if present
        if (this.certs && this.certs.length > 0) {
            const certsElement = new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT_SPECIFIC
                    tagNumber: 0, // [0]
                },
                value: [this.certs.toAsn1()],
            })
            sequence.valueBlock.value.push(certsElement)
        }

        // Add crls if present
        if (this.crls && this.crls.length > 0) {
            const crlsElement = new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT_SPECIFIC
                    tagNumber: 1, // [1]
                },
                value: [this.crls.toAsn1()],
            })
            sequence.valueBlock.value.push(crlsElement)
        }

        return sequence
    }

    /**
     * Creates an OriginatorInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1BaseBlock): OriginatorInfo {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OriginatorInfo',
            )
        }

        let certs: CertificateSet | undefined
        let crls: RevocationInfoChoices | undefined

        for (const element of asn1.valueBlock.value) {
            if (!(element instanceof asn1js.Constructed)) {
                continue
            }

            const tagClass = element.idBlock.tagClass
            const tagNumber = element.idBlock.tagNumber

            if (tagClass === 3) {
                // CONTEXT_SPECIFIC
                if (tagNumber === 0) {
                    // [0] certs
                    if (element.valueBlock.value.length > 0) {
                        certs = CertificateSet.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    }
                } else if (tagNumber === 1) {
                    // [1] crls
                    if (element.valueBlock.value.length > 0) {
                        crls = RevocationInfoChoices.fromAsn1(
                            element.valueBlock.value[0],
                        )
                    }
                }
            }
        }

        return new OriginatorInfo({ certs, crls })
    }
}

// Export these classes for use in other modules
export { CertificateSet, RevocationInfoChoices }
