[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / Sequence

# Class: Sequence

## Extends

- [`Constructed`](Constructed.md)

## Constructors

### Constructor

> **new Sequence**(`parameters?`): `Sequence`

#### Parameters

##### parameters?

[`ConstructedParams`](../interfaces/ConstructedParams.md)

#### Returns

`Sequence`

#### Overrides

[`Constructed`](Constructed.md).[`constructor`](Constructed.md#constructor)

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

[`Constructed`](Constructed.md).[`blockLength`](Constructed.md#blocklength)

---

### error

> **error**: `string`

#### Inherited from

[`Constructed`](Constructed.md).[`error`](Constructed.md#error)

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

[`Constructed`](Constructed.md).[`idBlock`](Constructed.md#idblock)

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

[`Constructed`](Constructed.md).[`lenBlock`](Constructed.md#lenblock)

---

### name

> **name**: `string`

#### Inherited from

[`Constructed`](Constructed.md).[`name`](Constructed.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`Constructed`](Constructed.md).[`optional`](Constructed.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`Constructed`](Constructed.md).[`primitiveSchema`](Constructed.md#primitiveschema)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

[`Constructed`](Constructed.md).[`valueBeforeDecodeView`](Constructed.md#valuebeforedecodeview)

---

### valueBlock

> **valueBlock**: `LocalConstructedValueBlock`

#### Inherited from

[`Constructed`](Constructed.md).[`valueBlock`](Constructed.md#valueblock)

---

### warnings

> **warnings**: `string`[]

#### Inherited from

[`Constructed`](Constructed.md).[`warnings`](Constructed.md#warnings)

---

### NAME

> `static` **NAME**: `string`

Name of the block

#### Overrides

[`Constructed`](Constructed.md).[`NAME`](Constructed.md#name-1)

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

[`Constructed`](Constructed.md).[`valueBeforeDecode`](Constructed.md#valuebeforedecode)

## Methods

### fromBER()

> **fromBER**(`inputBuffer`, `inputOffset`, `inputLength`): `number`

Base function for converting block from BER encoded array of bytes

#### Parameters

##### inputBuffer

ASN.1 BER encoded array

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

##### inputOffset

`number`

Offset in ASN.1 BER encoded array where decoding should be started

##### inputLength

`number`

Maximum length of array of bytes which can be using in this function

#### Returns

`number`

Offset after least decoded byte

#### Inherited from

[`Constructed`](Constructed.md).[`fromBER`](Constructed.md#fromber)

---

### isEqual()

> **isEqual**(`other`): `other is Sequence`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is Sequence`

#### Inherited from

[`Constructed`](Constructed.md).[`isEqual`](Constructed.md#isequal)

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

[`Constructed`](Constructed.md).[`onAsciiEncoding`](Constructed.md#onasciiencoding)

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

#### Inherited from

[`Constructed`](Constructed.md).[`toBER`](Constructed.md#tober)

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalConstructedValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalConstructedValueBlockJson`\>

JSON object

#### Inherited from

[`Constructed`](Constructed.md).[`toJSON`](Constructed.md#tojson)

---

### toString()

> **toString**(`encoding?`): `string`

Returns a string representation of an object.

#### Parameters

##### encoding?

[`StringEncoding`](../type-aliases/StringEncoding.md)

#### Returns

`string`

#### Inherited from

[`Constructed`](Constructed.md).[`toString`](Constructed.md#tostring)

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

[`Constructed`](Constructed.md).[`blockName`](Constructed.md#blockname)
