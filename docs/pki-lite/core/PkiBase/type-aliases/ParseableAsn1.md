[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / ParseableAsn1

# Type Alias: ParseableAsn1\<T\>

> **ParseableAsn1**\<`T`\> = `object`

Interface for types that can be parsed from ASN.1 or DER encoding.

## Type Parameters

### T

`T`

The type that can be parsed

## Methods

### fromAsn1()?

> `optional` **fromAsn1**(`asn1`): `T`

#### Parameters

##### asn1

[`Asn1BaseBlock`](Asn1BaseBlock.md)

#### Returns

`T`

---

### fromDer()?

> `optional` **fromDer**(`der`): `T`

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

#### Returns

`T`
