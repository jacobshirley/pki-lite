[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/tagging](../README.md) / implicitTag

# Function: implicitTag()

> **implicitTag**\<`T`\>(`block`, `tagNumber`): `T`

Re-tags a block with a context-specific tag, i.e. applies an IMPLICIT tag.

The X.509 / CMS ASN.1 modules use IMPLICIT TAGS, so a `[n] Type` field is encoded as
the underlying value with its universal tag replaced by `[n]` (and nothing wrapped
around it). Only a tagged CHOICE (e.g. `directoryName [4] Name`) is EXPLICIT.

asn1js (3.0.10) has no helper or constants for implicit tagging; the supported way is
to set the block's `idBlock`, which is all this does. Going the other way (reading a
context-tagged value as its universal type) is done at the call sites by building the
asn1js block (`Sequence`, `Integer`, `BitString`, ...) from the parsed children/content.

## Type Parameters

### T

`T` _extends_ [`Asn1BaseBlock`](../../PkiBase/type-aliases/Asn1BaseBlock.md)

## Parameters

### block

`T`

### tagNumber

`number`

## Returns

`T`
