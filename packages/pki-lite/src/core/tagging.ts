import { Asn1BaseBlock, asn1js } from './PkiBase.js'
import { Asn1ParseError } from './errors/Asn1ParseError.js'

/**
 * Re-tags a block with a context-specific tag, i.e. applies an IMPLICIT tag.
 *
 * The X.509 / CMS ASN.1 modules use IMPLICIT TAGS, so a `[n] Type` field is encoded as
 * the underlying value with its universal tag replaced by `[n]` (and nothing wrapped
 * around it). Only a tagged CHOICE (e.g. `directoryName [4] Name`) is EXPLICIT.
 *
 * asn1js (3.0.10) has no helper or constants for implicit tagging; the supported way is
 * to set the block's `idBlock`, which is all this does. Going the other way (reading a
 * context-tagged value as its universal type) is done at the call sites by building the
 * asn1js block (`Sequence`, `Integer`, `BitString`, ...) from the parsed children/content.
 */
export function implicitTag<T extends Asn1BaseBlock>(
    block: T,
    tagNumber: number,
): T {
    block.idBlock.tagClass = 3 // CONTEXT-SPECIFIC
    block.idBlock.tagNumber = tagNumber
    return block
}

/** Whether a block carries the context-specific tag `[tagNumber]`. */
export const isContextTag = (asn1: Asn1BaseBlock, tagNumber: number) =>
    asn1.idBlock.tagClass === 3 && asn1.idBlock.tagNumber === tagNumber

/**
 * Reads an IMPLICIT `[n]` tag over a SEQUENCE type back as the SEQUENCE: the parsed
 * context-tagged block is a plain constructed block holding the SEQUENCE's elements.
 */
export function implicitSequence(block: Asn1BaseBlock): asn1js.Sequence {
    const value = (block.valueBlock as { value?: Asn1BaseBlock[] }).value
    if (!block.idBlock.isConstructed || !Array.isArray(value)) {
        throw new Asn1ParseError(
            'Invalid ASN.1 structure: expected a constructed value',
        )
    }
    return new asn1js.Sequence({ value })
}
