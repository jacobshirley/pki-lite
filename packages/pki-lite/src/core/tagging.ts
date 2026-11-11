import { Asn1Node } from './der/Asn1Node.js'

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
