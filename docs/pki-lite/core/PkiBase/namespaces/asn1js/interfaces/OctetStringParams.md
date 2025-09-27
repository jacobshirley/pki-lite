[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / OctetStringParams

# Interface: OctetStringParams

## Extends

- [`BaseBlockParams`](BaseBlockParams.md).`LocalOctetStringValueBlockParams`

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

[`BaseBlockParams`](BaseBlockParams.md).[`idBlock`](BaseBlockParams.md#idblock)

---

### isConstructed?

> `optional` **isConstructed**: `boolean`

#### Inherited from

`LocalOctetStringValueBlockParams.isConstructed`

---

### isHexOnly?

> `optional` **isHexOnly**: `boolean`

#### Inherited from

[`IHexBlock`](IHexBlock.md).[`isHexOnly`](IHexBlock.md#ishexonly)

---

### isIndefiniteForm?

> `optional` **isIndefiniteForm**: `boolean`

#### Inherited from

`LocalOctetStringValueBlockParams.isIndefiniteForm`

---

### lenBlock?

> `optional` **lenBlock**: `Partial`\<`ILocalLengthBlock`\>

#### Inherited from

[`BaseBlockParams`](BaseBlockParams.md).[`lenBlock`](BaseBlockParams.md#lenblock)

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

> `optional` **value**: [`OctetString`](../classes/OctetString.md)[]

#### Inherited from

`LocalOctetStringValueBlockParams.value`

---

### valueBeforeDecode?

> `optional` **valueBeforeDecode**: `BufferSource`

#### Inherited from

[`BaseBlockParams`](BaseBlockParams.md).[`valueBeforeDecode`](BaseBlockParams.md#valuebeforedecode)

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
