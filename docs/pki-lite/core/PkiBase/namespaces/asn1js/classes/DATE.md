[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / DATE

# Class: DATE

## Extends

- [`Utf8String`](Utf8String.md)

## Constructors

### Constructor

> **new DATE**(`parameters?`): `DATE`

#### Parameters

##### parameters?

[`Utf8StringParams`](../interfaces/Utf8StringParams.md)

#### Returns

`DATE`

#### Overrides

[`Utf8String`](Utf8String.md).[`constructor`](Utf8String.md#constructor)

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

[`Utf8String`](Utf8String.md).[`blockLength`](Utf8String.md#blocklength)

---

### error

> **error**: `string`

#### Inherited from

[`Utf8String`](Utf8String.md).[`error`](Utf8String.md#error)

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

[`Utf8String`](Utf8String.md).[`idBlock`](Utf8String.md#idblock)

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

[`Utf8String`](Utf8String.md).[`lenBlock`](Utf8String.md#lenblock)

---

### name

> **name**: `string`

#### Inherited from

[`Utf8String`](Utf8String.md).[`name`](Utf8String.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`Utf8String`](Utf8String.md).[`optional`](Utf8String.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`Utf8String`](Utf8String.md).[`primitiveSchema`](Utf8String.md#primitiveschema)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

[`Utf8String`](Utf8String.md).[`valueBeforeDecodeView`](Utf8String.md#valuebeforedecodeview)

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

[`Utf8String`](Utf8String.md).[`valueBlock`](Utf8String.md#valueblock)

---

### warnings

> **warnings**: `string`[]

#### Inherited from

[`Utf8String`](Utf8String.md).[`warnings`](Utf8String.md#warnings)

---

### NAME

> `static` **NAME**: `string`

#### Overrides

[`Utf8String`](Utf8String.md).[`NAME`](Utf8String.md#name-1)

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

[`Utf8String`](Utf8String.md).[`valueBeforeDecode`](Utf8String.md#valuebeforedecode)

## Methods

### fromBER()

> **fromBER**(`inputBuffer`, `inputOffset`, `inputLength`): `number`

#### Parameters

##### inputBuffer

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

##### inputOffset

`number`

##### inputLength

`number`

#### Returns

`number`

#### Inherited from

[`Utf8String`](Utf8String.md).[`fromBER`](Utf8String.md#fromber)

---

### fromBuffer()

> **fromBuffer**(`inputBuffer`): `void`

#### Parameters

##### inputBuffer

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`void`

#### Inherited from

[`Utf8String`](Utf8String.md).[`fromBuffer`](Utf8String.md#frombuffer)

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Inherited from

[`Utf8String`](Utf8String.md).[`fromString`](Utf8String.md#fromstring)

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

[`Utf8String`](Utf8String.md).[`getValue`](Utf8String.md#getvalue)

---

### isEqual()

> **isEqual**(`other`): `other is DATE`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is DATE`

#### Inherited from

[`Utf8String`](Utf8String.md).[`isEqual`](Utf8String.md#isequal)

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

[`Utf8String`](Utf8String.md).[`onAsciiEncoding`](Utf8String.md#onasciiencoding)

---

### setValue()

> **setValue**(`value`): `void`

String value

#### Parameters

##### value

`string`

String value

#### Returns

`void`

#### Since

3.0.0

#### Inherited from

[`Utf8String`](Utf8String.md).[`setValue`](Utf8String.md#setvalue)

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

[`Utf8String`](Utf8String.md).[`toBER`](Utf8String.md#tober)

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

JSON object

#### Inherited from

[`Utf8String`](Utf8String.md).[`toJSON`](Utf8String.md#tojson)

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

[`Utf8String`](Utf8String.md).[`toString`](Utf8String.md#tostring)

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

[`Utf8String`](Utf8String.md).[`blockName`](Utf8String.md#blockname)
