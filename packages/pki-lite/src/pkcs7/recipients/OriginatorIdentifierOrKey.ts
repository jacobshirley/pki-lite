import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { OriginatorPublicKey } from './OriginatorPublicKey.js'
import { Asn1Node, Choice, der, TagClass } from '../../core/PkiBase.js'
import { SubjectKeyIdentifier } from '../../keys/SubjectKeyIdentifier.js'
import { Asn1ParseError } from '../../core/errors/Asn1ParseError.js'

/**
 * Represents an OriginatorIdentifierOrKey structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * OriginatorIdentifierOrKey ::= CHOICE {
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   subjectKeyIdentifier [0] SubjectKeyIdentifier,
 *   originatorKey [1] OriginatorPublicKey }
 * ```
 */
export type OriginatorIdentifierOrKey =
    | IssuerAndSerialNumber
    | SubjectKeyIdentifier
    | OriginatorPublicKey

export const OriginatorIdentifierOrKey = Choice('OriginatorIdentifierOrKey', {
    IssuerAndSerialNumber,
    SubjectKeyIdentifier,
    OriginatorPublicKey,
    fromAsn1: (asn1: Asn1Node): OriginatorIdentifierOrKey => {
        // If it's a context-specific tag
        if (asn1.tagClass === TagClass.Context) {
            const tagNumber = asn1.tag

            // SubjectKeyIdentifier [0]
            if (tagNumber === 0) {
                return SubjectKeyIdentifier.fromAsn1(asn1)
            }

            // OriginatorPublicKey [1]
            if (tagNumber === 1) {
                // [1] IMPLICIT OriginatorPublicKey: restore the SEQUENCE tag
                return OriginatorPublicKey.fromAsn1(der.sequence(asn1.children))
            }

            throw new Asn1ParseError(`Unsupported tag number: ${tagNumber}`)
        }

        // Default to IssuerAndSerialNumber
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
    toAsn1: (value: OriginatorIdentifierOrKey): Asn1Node => {
        let asn1 = value.toAsn1()
        if (value instanceof SubjectKeyIdentifier) {
            asn1 = asn1.implicit(0) // [0] IMPLICIT
        } else if (value instanceof OriginatorPublicKey) {
            asn1 = asn1.implicit(1) // [1] IMPLICIT
        } else if (!(value instanceof IssuerAndSerialNumber)) {
            throw new Asn1ParseError(`Unsupported type: ${typeof value}`)
        }

        return asn1
    },
})
