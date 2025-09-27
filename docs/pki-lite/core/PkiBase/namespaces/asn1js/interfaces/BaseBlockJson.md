[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / BaseBlockJson

# Interface: BaseBlockJson\<T\>

## Extends

- `LocalBaseBlockJson`.`Omit`\<[`IBaseBlock`](IBaseBlock.md), `"primitiveSchema"`\>

## Extended by

- [`ObjectIdentifierJson`](ObjectIdentifierJson.md)
- [`RelativeObjectIdentifierJson`](RelativeObjectIdentifierJson.md)
- [`UTCTimeJson`](UTCTimeJson.md)

## Type Parameters

### T

`T` _extends_ `LocalBaseBlockJson` = `LocalBaseBlockJson`

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

`LocalBaseBlockJson.blockLength`

---

### blockName

> **blockName**: `string`

#### Inherited from

`LocalBaseBlockJson.blockName`

---

### error

> **error**: `string`

#### Inherited from

`LocalBaseBlockJson.error`

---

### idBlock

> **idBlock**: `LocalIdentificationBlockJson`

---

### lenBlock

> **lenBlock**: `LocalLengthBlockJson`

---

### name

> **name**: `string`

#### Inherited from

[`IBaseBlock`](IBaseBlock.md).[`name`](IBaseBlock.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`IBaseBlock`](IBaseBlock.md).[`optional`](IBaseBlock.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: `BaseBlockJson`\<`LocalBaseBlockJson`\>

---

### valueBeforeDecode

> **valueBeforeDecode**: `string`

#### Inherited from

`LocalBaseBlockJson.valueBeforeDecode`

---

### valueBlock

> **valueBlock**: `T`

---

### warnings

> **warnings**: `string`[]

#### Inherited from

`LocalBaseBlockJson.warnings`
