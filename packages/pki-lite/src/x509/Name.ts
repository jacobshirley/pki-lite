import { Asn1BaseBlock, Choice } from '../core/PkiBase.js'
import { RDNSequence } from './RDNSequence.js'

/**
 * Represents a Name.
 *
 * @asn
 * ```asn
 * Name ::= CHOICE {
 *   -- only one possibility for now --
 *   rdnSequence  RDNSequence
 * }
 * ```
 */
export type Name = RDNSequence
export const Name = Choice('Name', {
    RDNSequence,
    fromAsn1(asn1: Asn1BaseBlock): Name {
        return RDNSequence.fromAsn1(asn1)
    },
    parse(humanString: string): Name {
        return RDNSequence.parse(humanString)
    },
})
