import { Asn1Node } from './der/Asn1Node.js'
import { UniversalTag } from './der/Asn1Node.js'
import { Asn1ParseError } from './errors/Asn1ParseError.js'

/**
 * Re-tags a node with a context-specific tag, i.e. applies an IMPLICIT tag.
 *
 * The X.509 / CMS ASN.1 modules use IMPLICIT TAGS, so a `[n] Type` field is encoded as
 * the underlying value with its universal tag replaced by `[n]` (and nothing wrapped
 * around it). Only a tagged CHOICE (e.g. `directoryName [4] Name`) is EXPLICIT.
 *
 * Returns a new node; the input is not modified. Going the other way (reading a
 * context-tagged value as its universal type) is `node.retag(UniversalTag.X)`.
 */
export function implicitTag(block: Asn1Node, tagNumber: number): Asn1Node {
    return block.implicit(tagNumber)
}

/** Whether a node carries the context-specific tag `[tagNumber]`. */
export const isContextTag = (asn1: Asn1Node, tagNumber: number) =>
    asn1.isContext(tagNumber)

/**
 * Reads an IMPLICIT `[n]` tag over a SEQUENCE type back as the SEQUENCE: the parsed
 * context-tagged node is a constructed node holding the SEQUENCE's elements.
 */
export function implicitSequence(block: Asn1Node): Asn1Node {
    if (!block.constructed) {
        throw new Asn1ParseError(
            'Invalid ASN.1 structure: expected a constructed value',
        )
    }
    return block.retag(UniversalTag.Sequence)
}

/**
 * Reads an IMPLICIT `[n] SEQUENCE OF X`, where each X is itself a SEQUENCE (e.g.
 * `[1] IMPLICIT Extensions`), back as the SEQUENCE. Earlier versions of this library
 * wrote the SEQUENCE wrapped inside the [n] (explicit tagging); that form - a single
 * SEQUENCE child whose own elements are all SEQUENCEs - is still accepted.
 */
export function implicitSequenceOf(block: Asn1Node): Asn1Node {
    const sequence = implicitSequence(block)
    const [only] = sequence.children
    if (
        sequence.children.length === 1 &&
        only.is(UniversalTag.Sequence) &&
        only.children.every((item) => item.is(UniversalTag.Sequence))
    ) {
        return only
    }
    return sequence
}
