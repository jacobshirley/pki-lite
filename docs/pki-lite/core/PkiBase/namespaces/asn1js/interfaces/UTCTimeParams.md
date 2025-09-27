[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / UTCTimeParams

# Interface: UTCTimeParams

## Extends

- [`VisibleStringParams`](../type-aliases/VisibleStringParams.md)

## Properties

### blockLength?

> `optional` **blockLength**: `number`

#### Inherited from

[`BaseBlockJson`](BaseBlockJson.md).[`blockLength`](BaseBlockJson.md#blocklength)

---

### error?

> `optional` **error**: `string`

#### Inherited from

[`BaseBlockJson`](BaseBlockJson.md).[`error`](BaseBlockJson.md#error)

---

### idBlock?

> `optional` **idBlock**: `Partial`\<`ILocalIdentificationBlock`\> & `Partial`\<[`IHexBlock`](IHexBlock.md)\>

#### Inherited from

`VisibleStringParams.idBlock`

---

### lenBlock?

> `optional` **lenBlock**: `Partial`\<`ILocalLengthBlock`\>

#### Inherited from

`VisibleStringParams.lenBlock`

---

### name?

> `optional` **name**: `string`

#### Inherited from

[`IBaseBlock`](IBaseBlock.md).[`name`](IBaseBlock.md#name)

---

### optional?

> `optional` **optional**: `boolean`

#### Inherited from

[`IBaseBlock`](IBaseBlock.md).[`optional`](IBaseBlock.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](../classes/BaseBlock.md)\<[`ValueBlock`](../classes/ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`IBaseBlock`](IBaseBlock.md).[`primitiveSchema`](IBaseBlock.md#primitiveschema)

---

### value?

> `optional` **value**: `string`

#### Overrides

`VisibleStringParams.value`

---

### valueBeforeDecode?

> `optional` **valueBeforeDecode**: `BufferSource`

#### Inherited from

`VisibleStringParams.valueBeforeDecode`

---

### valueDate?

> `optional` **valueDate**: `Date`

---

### valueHex?

> `optional` **valueHex**: `BufferSource`

#### Inherited from

[`IHexBlock`](IHexBlock.md).[`valueHex`](IHexBlock.md#valuehex)

---

### warnings?

> `optional` **warnings**: `string`[]

#### Inherited from

[`BaseBlockJson`](BaseBlockJson.md).[`warnings`](BaseBlockJson.md#warnings)
