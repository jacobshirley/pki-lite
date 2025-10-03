[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / RelativeObjectIdentifier

# Class: RelativeObjectIdentifier

## Extends

- [`BaseBlock`](BaseBlock.md)\<`LocalRelativeObjectIdentifierValueBlock`, `LocalRelativeObjectIdentifierValueBlockJson`\>

## Constructors

### Constructor

> **new RelativeObjectIdentifier**(`parameters?`): `RelativeObjectIdentifier`

#### Parameters

##### parameters?

[`RelativeObjectIdentifierParams`](../interfaces/RelativeObjectIdentifierParams.md)

#### Returns

`RelativeObjectIdentifier`

#### Overrides

[`BaseBlock`](BaseBlock.md).[`constructor`](BaseBlock.md#constructor)

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`blockLength`](BaseBlock.md#blocklength)

---

### error

> **error**: `string`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`error`](BaseBlock.md#error)

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`idBlock`](BaseBlock.md#idblock)

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`lenBlock`](BaseBlock.md#lenblock)

---

### name

> **name**: `string`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`name`](BaseBlock.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`optional`](BaseBlock.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`primitiveSchema`](BaseBlock.md#primitiveschema)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`valueBeforeDecodeView`](BaseBlock.md#valuebeforedecodeview)

---

### valueBlock

> **valueBlock**: `LocalRelativeObjectIdentifierValueBlock`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`valueBlock`](BaseBlock.md#valueblock)

---

### warnings

> **warnings**: `string`[]

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`warnings`](BaseBlock.md#warnings)

---

### NAME

> `static` **NAME**: `string`

Name of the block

#### Overrides

[`BaseBlock`](BaseBlock.md).[`NAME`](BaseBlock.md#name-1)

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

[`BaseBlock`](BaseBlock.md).[`valueBeforeDecode`](BaseBlock.md#valuebeforedecode)

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

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`fromBER`](BaseBlock.md#fromber)

---

### getValue()

> **getValue**(): `string`

Gets string representation of Relative Object Identifier

#### Returns

`string`

#### Since

3.0.0

---

### isEqual()

> **isEqual**(`other`): `other is RelativeObjectIdentifier`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is RelativeObjectIdentifier`

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`isEqual`](BaseBlock.md#isequal)

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Overrides

[`BaseBlock`](BaseBlock.md).[`onAsciiEncoding`](BaseBlock.md#onasciiencoding)

---

### setValue()

> **setValue**(`value`): `void`

Sets Relative Object Identifier value from string

#### Parameters

##### value

`string`

String value

#### Returns

`void`

#### Since

3.0.0

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

[`BaseBlock`](BaseBlock.md).[`toBER`](BaseBlock.md#tober)

---

### toJSON()

> **toJSON**(): [`RelativeObjectIdentifierJson`](../interfaces/RelativeObjectIdentifierJson.md)

Returns a JSON representation of an object

#### Returns

[`RelativeObjectIdentifierJson`](../interfaces/RelativeObjectIdentifierJson.md)

JSON object

#### Overrides

[`BaseBlock`](BaseBlock.md).[`toJSON`](BaseBlock.md#tojson)

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

[`BaseBlock`](BaseBlock.md).[`toString`](BaseBlock.md#tostring)

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

[`BaseBlock`](BaseBlock.md).[`blockName`](BaseBlock.md#blockname)
