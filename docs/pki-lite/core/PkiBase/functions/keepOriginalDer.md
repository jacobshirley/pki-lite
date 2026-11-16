[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / keepOriginalDer

# Function: keepOriginalDer()

> **keepOriginalDer**(`target`, `parsed`): `void`

**`Internal`**

Keeps the bytes `target` was parsed from, for [PkiBase.toOriginalDer](../classes/PkiBase.md#tooriginalder). Called at
the end of `fromAsn1` by types whose encoding a signature covers.

## Parameters

### target

`object` & `object`

### parsed

[`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

## Returns

`void`
