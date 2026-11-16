import { CertificateSet } from '../../x509/CertificateSet.js'
import {
    Asn1Node,
    der,
    PkiBase,
    TagClass,
    UniversalTag,
} from '../../core/PkiBase.js'
import { RevocationInfoChoices } from '../../revocation/RevocationInfoChoices.js'
import { RevocationInfoChoice } from '../../revocation/RevocationInfoChoice.js'
import { CertificateChoices } from '../../x509/CertificateChoices.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'
import { implicitTag } from '../../core/tagging.js'

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
    toAsn1(): Asn1Node {
        const values: Asn1Node[] = []

        // certs [0] IMPLICIT CertificateSet
        if (this.certs && this.certs.length > 0) {
            values.push(implicitTag(this.certs.toAsn1(), 0))
        }

        // crls [1] IMPLICIT RevocationInfoChoices
        if (this.crls && this.crls.length > 0) {
            values.push(implicitTag(this.crls.toAsn1(), 1))
        }

        return der.sequence(values)
    }

    /**
     * Creates an OriginatorInfo from an ASN.1 structure.
     */
    static fromAsn1(asn1: Asn1Node): OriginatorInfo {
        if (!asn1.is(UniversalTag.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected Sequence for OriginatorInfo',
            )
        }

        let certs: CertificateSet | undefined
        let crls: RevocationInfoChoices | undefined

        for (const element of asn1.children) {
            if (!element?.constructed) {
                continue
            }

            const tagNumber = element.tag

            if (element.tagClass === TagClass.Context) {
                // CONTEXT_SPECIFIC
                if (tagNumber === 0) {
                    // certs [0] IMPLICIT CertificateSet
                    certs = CertificateSet.fromAsn1(implicitSet(element))
                } else if (tagNumber === 1) {
                    // crls [1] IMPLICIT RevocationInfoChoices
                    crls = RevocationInfoChoices.fromAsn1(implicitSet(element))
                }
            }
        }

        return new OriginatorInfo({ certs, crls })
    }
}

// Export these classes for use in other modules
export { CertificateSet, RevocationInfoChoices }

/**
 * Reads a `[n] IMPLICIT SET OF` field back as the SET. Earlier versions of this
 * library wrote the SET wrapped inside the [n] (explicit tagging); that form is
 * recognised by its single universal SET child and still accepted.
 */
function implicitSet(element: Asn1Node): Asn1Node {
    const children = element.items('a constructed value')
    if (children.length === 1 && children[0].is(UniversalTag.Set)) {
        return children[0]
    }
    return element.retag(UniversalTag.Set)
}
