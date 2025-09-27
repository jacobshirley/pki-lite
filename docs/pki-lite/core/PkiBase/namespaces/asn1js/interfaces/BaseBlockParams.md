[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / BaseBlockParams

# Interface: BaseBlockParams

## Extends

- `LocalBaseBlockParams`.`LocalIdentificationBlockParams`.`LocalLengthBlockParams`.`Partial`\<[`IBaseBlock`](IBaseBlock.md)\>

## Extended by

- [`BaseStringBlockParams`](BaseStringBlockParams.md)
- [`BitStringParams`](BitStringParams.md)
- [`BooleanParams`](BooleanParams.md)
- [`ConstructedParams`](ConstructedParams.md)
- [`IntegerParams`](IntegerParams.md)
- [`ObjectIdentifierParams`](ObjectIdentifierParams.md)
- [`OctetStringParams`](OctetStringParams.md)
- [`PrimitiveParams`](PrimitiveParams.md)
- [`RelativeObjectIdentifierParams`](RelativeObjectIdentifierParams.md)

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

`LocalIdentificationBlockParams.idBlock`

---

### lenBlock?

> `optional` **lenBlock**: `Partial`\<`ILocalLengthBlock`\>

#### Inherited from

`LocalLengthBlockParams.lenBlock`

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

### valueBeforeDecode?

> `optional` **valueBeforeDecode**: `BufferSource`

#### Inherited from

`LocalBaseBlockParams.valueBeforeDecode`

---

### warnings?

> `optional` **warnings**: `string`[]

#### Inherited from

[`BaseBlockJson`](BaseBlockJson.md).[`warnings`](BaseBlockJson.md#warnings)
