import { OctetString } from '../../asn1/OctetString.js'

/**
 * Represents a KeyIdentifier structure as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * KeyIdentifier ::= OCTET STRING
 * ```
 */
export type KeyIdentifier = OctetString
export const KeyIdentifier = OctetString
