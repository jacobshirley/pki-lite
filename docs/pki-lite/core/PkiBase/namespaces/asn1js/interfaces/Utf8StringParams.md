[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / Utf8StringParams

# Interface: Utf8StringParams

## Extends

- [`BaseStringBlockParams`](BaseStringBlockParams.md).`LocalUtf8StringValueBlockParams`

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

[`BaseStringBlockParams`](BaseStringBlockParams.md).[`idBlock`](BaseStringBlockParams.md#idblock)

---

### lenBlock?

> `optional` **lenBlock**: `Partial`\<`ILocalLengthBlock`\>

#### Inherited from

[`BaseStringBlockParams`](BaseStringBlockParams.md).[`lenBlock`](BaseStringBlockParams.md#lenblock)

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

#### Inherited from

[`BaseStringBlockParams`](BaseStringBlockParams.md).[`value`](BaseStringBlockParams.md#value)

---

### valueBeforeDecode?

> `optional` **valueBeforeDecode**: `BufferSource`

#### Inherited from

[`BaseStringBlockParams`](BaseStringBlockParams.md).[`valueBeforeDecode`](BaseStringBlockParams.md#valuebeforedecode)

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
