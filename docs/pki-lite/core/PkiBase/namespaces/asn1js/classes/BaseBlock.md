[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / BaseBlock

# Class: BaseBlock\<T, J\>

## Extends

- `LocalBaseBlock`

## Extended by

- [`BaseStringBlock`](BaseStringBlock.md)
- [`BitString`](BitString.md)
- [`Boolean`](Boolean.md)
- [`Constructed`](Constructed.md)
- [`EndOfContent`](EndOfContent.md)
- [`Integer`](Integer.md)
- [`Null`](Null.md)
- [`ObjectIdentifier`](ObjectIdentifier.md)
- [`OctetString`](OctetString.md)
- [`Primitive`](Primitive.md)
- [`RelativeObjectIdentifier`](RelativeObjectIdentifier.md)

## Type Parameters

### T

`T` _extends_ [`ValueBlock`](ValueBlock.md) = [`ValueBlock`](ValueBlock.md)

### J

`J` _extends_ [`ValueBlockJson`](../type-aliases/ValueBlockJson.md) = [`ValueBlockJson`](../type-aliases/ValueBlockJson.md)

## Implements

- [`IBaseBlock`](../interfaces/IBaseBlock.md)
- [`IBerConvertible`](../interfaces/IBerConvertible.md)

## Constructors

### Constructor

> **new BaseBlock**\<`T`, `J`\>(`__namedParameters?`, `valueBlockType?`): `BaseBlock`\<`T`, `J`\>

#### Parameters

##### \_\_namedParameters?

[`BaseBlockParams`](../interfaces/BaseBlockParams.md)

##### valueBlockType?

[`ValueBlockConstructor`](../type-aliases/ValueBlockConstructor.md)\<`T`\>

#### Returns

`BaseBlock`\<`T`, `J`\>

#### Overrides

`LocalBaseBlock.constructor`

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

`LocalBaseBlock.blockLength`

---

### error

> **error**: `string`

#### Inherited from

`LocalBaseBlock.error`

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

---

### name

> **name**: `string`

#### Implementation of

[`IBaseBlock`](../interfaces/IBaseBlock.md).[`name`](../interfaces/IBaseBlock.md#name)

---

### optional

> **optional**: `boolean`

#### Implementation of

[`IBaseBlock`](../interfaces/IBaseBlock.md).[`optional`](../interfaces/IBaseBlock.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: `BaseBlock`\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Implementation of

[`IBaseBlock`](../interfaces/IBaseBlock.md).[`primitiveSchema`](../interfaces/IBaseBlock.md#primitiveschema)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

`LocalBaseBlock.valueBeforeDecodeView`

---

### valueBlock

> **valueBlock**: `T`

---

### warnings

> **warnings**: `string`[]

#### Inherited from

`LocalBaseBlock.warnings`

---

### NAME

> `static` **NAME**: `string`

Name of the block

#### Overrides

`LocalBaseBlock.NAME`

## Accessors

### valueBeforeDecode

#### Get Signature

> **get** **valueBeforeDecode**(): `ArrayBuffer`

##### Deprecated

since version 3.0.0

##### Returns

`ArrayBuffer`

#### Set Signature

> **set** **valueBeforeDecode**(`value`): `void`

##### Deprecated

since version 3.0.0

##### Parameters

###### value

`ArrayBuffer`

##### Returns

`void`

#### Inherited from

`LocalBaseBlock.valueBeforeDecode`

## Methods

### fromBER()

> **fromBER**(`inputBuffer`, `inputOffset`, `inputLength`): `number`

Base function for converting block from BER encoded array of bytes

#### Parameters

##### inputBuffer

`Uint8Array`

ASN.1 BER encoded array

##### inputOffset

`number`

Offset in ASN.1 BER encoded array where decoding should be started

##### inputLength

`number`

Maximum length of array of bytes which can be using in this function

#### Returns

`number`

Offset after least decoded byte

#### Implementation of

[`IBerConvertible`](../interfaces/IBerConvertible.md).[`fromBER`](../interfaces/IBerConvertible.md#fromber)

---

### isEqual()

> **isEqual**(`other`): `other is BaseBlock<T, J>`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is BaseBlock<T, J>`

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

---

### toBER()

> **toBER**(`sizeOnly?`, `writer?`): `ArrayBuffer`

Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)

#### Parameters

##### sizeOnly?

`boolean`

Flag that we need only a size of encoding, not a real array of bytes

##### writer?

[`ViewWriter`](ViewWriter.md)

#### Returns

`ArrayBuffer`

ASN.1 BER encoded array

#### Implementation of

[`IBerConvertible`](../interfaces/IBerConvertible.md).[`toBER`](../interfaces/IBerConvertible.md#tober)

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`J`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`J`\>

JSON object

#### Overrides

`LocalBaseBlock.toJSON`

---

### toString()

> **toString**(`encoding?`): `string`

Returns a string representation of an object.

#### Parameters

##### encoding?

[`StringEncoding`](../type-aliases/StringEncoding.md)

#### Returns

`string`

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

`LocalBaseBlock.blockName`
