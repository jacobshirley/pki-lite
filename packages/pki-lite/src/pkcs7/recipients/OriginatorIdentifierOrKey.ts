import { IssuerAndSerialNumber } from '../IssuerAndSerialNumber.js'
import { OriginatorPublicKey } from './OriginatorPublicKey.js'
import { Asn1BaseBlock, asn1js, Choice } from '../../core/PkiBase.js'
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
    fromAsn1: (asn1: Asn1BaseBlock): OriginatorIdentifierOrKey => {
        // If it's a context-specific tag
        if (asn1.idBlock.tagClass === 3) {
            const tagNumber = asn1.idBlock.tagNumber

            // SubjectKeyIdentifier [0]
            if (tagNumber === 0) {
                return SubjectKeyIdentifier.fromAsn1(asn1)
            }

            // OriginatorPublicKey [1]
            if (tagNumber === 1) {
                return OriginatorPublicKey.fromAsn1(asn1)
            }

            throw new Asn1ParseError(`Unsupported tag number: ${tagNumber}`)
        }

        // Default to IssuerAndSerialNumber
        return IssuerAndSerialNumber.fromAsn1(asn1)
    },
    toAsn1: (value: OriginatorIdentifierOrKey): Asn1BaseBlock => {
        const asn1 = value.toAsn1()
        if (value instanceof SubjectKeyIdentifier) {
            asn1.idBlock.tagClass = 3 // Context-specific
            asn1.idBlock.tagNumber = 0
        } else if (value instanceof OriginatorPublicKey) {
            asn1.idBlock.tagClass = 3 // Context-specific
            asn1.idBlock.tagNumber = 1
        } else if (!(value instanceof IssuerAndSerialNumber)) {
            throw new Asn1ParseError(`Unsupported type: ${typeof value}`)
        }

        return asn1
    },
})
