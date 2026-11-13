import { Asn1BaseBlock, asn1js, PkiSequence } from '../core/PkiBase.js'
import { RelativeDistinguishedName } from './RelativeDistinguishedName.js'
import { Asn1ParseError } from '../core/errors/Asn1ParseError.js'

/**
 * Represents a sequence of relative distinguished names (RDNs).
 *
 * @asn
 * ```asn
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * ```
 */
export class RDNSequence extends PkiSequence<RelativeDistinguishedName> {
    /**
     * Creates an RDNSequence from an ASN.1 structure.
     *
     * @param asn1 The ASN.1 structure
     * @returns An RDNSequence
     */
    static fromAsn1(asn1: Asn1BaseBlock): RDNSequence {
        if (!(asn1 instanceof asn1js.Sequence)) {
            throw new Asn1ParseError(
                'Invalid ASN.1 structure: expected SEQUENCE but got ' +
                    asn1.constructor.name,
            )
        }

        const rdnSequence = new RDNSequence()

        for (const rdnAsn1 of asn1.valueBlock.value) {
            const rdn = RelativeDistinguishedName.fromAsn1(rdnAsn1)
            rdnSequence.push(rdn)
        }

        return rdnSequence
    }

    toHumanString(): string {
        return this.map((rdn) => rdn.toHumanString()).join(', ')
    }

    /**
     * Whether this name matches another as RFC 5280 7.1 compares distinguished names: the
     * same number of RDNs, each matching (case, whitespace and string type do not matter;
     * see {@link AttributeTypeAndValue.matches}). Use it to compare a certificate's issuer
     * with its issuer's subject, rather than {@link equals}, which compares encodings.
     *
     * @example
     * ```typescript
     * cert.tbsCertificate.issuer.matches(ca.tbsCertificate.subject)
     * ```
     */
    matches(other: RDNSequence): boolean {
        return this.length === other.length && this.isWithin(other)
    }

    /**
     * Whether this name is within the subtree of `base` (RFC 5280 4.2.1.10): `base`'s RDNs
     * match the first RDNs of this name.
     *
     * @example
     * ```typescript
     * Name.parse('C=US, O=Example, CN=Alice').isWithin(Name.parse('C=US, O=Example')) // true
     * ```
     */
    isWithin(base: RDNSequence): boolean {
        return (
            base.length <= this.length &&
            base.every((rdn, i) => rdn.matches(this[i]))
        )
    }

    static parse(humanString: string | RDNSequence): RDNSequence {
        if (humanString instanceof RDNSequence) {
            return humanString
        }
        const rdnStrings = humanString.split(',').map((s) => s.trim())
        const rdnSequence = new RDNSequence()

        for (const rdnString of rdnStrings) {
            const rdn = RelativeDistinguishedName.parse(rdnString)
            rdnSequence.push(rdn)
        }

        return rdnSequence
    }
}
