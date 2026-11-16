[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/tagging](../README.md) / implicitSequenceOf

# Function: implicitSequenceOf()

> **implicitSequenceOf**(`block`): `Sequence`

Reads an IMPLICIT `[n] SEQUENCE OF X`, where each X is itself a SEQUENCE (e.g.
`[1] IMPLICIT Extensions`), back as the SEQUENCE. Earlier versions of this library
wrote the SEQUENCE wrapped inside the [n] (explicit tagging); that form - a single
SEQUENCE child whose own elements are all SEQUENCEs - is still accepted.

## Parameters

### block

[`Asn1BaseBlock`](../../PkiBase/type-aliases/Asn1BaseBlock.md)

## Returns

`Sequence`
