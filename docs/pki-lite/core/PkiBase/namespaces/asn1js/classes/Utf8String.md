[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / Utf8String

# Class: Utf8String

## Extends

- `LocalUtf8StringValueBlock`

## Extended by

- [`DATE`](DATE.md)
- [`DateTime`](DateTime.md)
- [`Duration`](Duration.md)
- [`TIME`](TIME.md)
- [`TimeOfDay`](TimeOfDay.md)

## Constructors

### Constructor

> **new Utf8String**(`parameters?`): `Utf8String`

#### Parameters

##### parameters?

[`Utf8StringParams`](../interfaces/Utf8StringParams.md)

#### Returns

`Utf8String`

#### Overrides

`LocalUtf8StringValueBlock.constructor`

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

`LocalUtf8StringValueBlock.blockLength`

---

### error

> **error**: `string`

#### Inherited from

`LocalUtf8StringValueBlock.error`

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

`LocalUtf8StringValueBlock.idBlock`

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

`LocalUtf8StringValueBlock.lenBlock`

---

### name

> **name**: `string`

#### Inherited from

`LocalUtf8StringValueBlock.name`

---

### optional

> **optional**: `boolean`

#### Inherited from

`LocalUtf8StringValueBlock.optional`

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

`LocalUtf8StringValueBlock.primitiveSchema`

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

`LocalUtf8StringValueBlock.valueBeforeDecodeView`

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

`LocalUtf8StringValueBlock.valueBlock`

---

### warnings

> **warnings**: `string`[]

#### Inherited from

`LocalUtf8StringValueBlock.warnings`

---

### NAME

> `static` **NAME**: `string`

#### Overrides

`LocalUtf8StringValueBlock.NAME`

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

`LocalUtf8StringValueBlock.valueBeforeDecode`

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

`LocalUtf8StringValueBlock.fromBER`

---

### fromBuffer()

> **fromBuffer**(`inputBuffer`): `void`

#### Parameters

##### inputBuffer

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`void`

#### Inherited from

`LocalUtf8StringValueBlock.fromBuffer`

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Inherited from

`LocalUtf8StringValueBlock.fromString`

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

`LocalUtf8StringValueBlock.getValue`

---

### isEqual()

> **isEqual**(`other`): `other is Utf8String`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is Utf8String`

#### Inherited from

`LocalUtf8StringValueBlock.isEqual`

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

`LocalUtf8StringValueBlock.onAsciiEncoding`

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

`LocalUtf8StringValueBlock.setValue`

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

`LocalUtf8StringValueBlock.toBER`

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

JSON object

#### Inherited from

`LocalUtf8StringValueBlock.toJSON`

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

`LocalUtf8StringValueBlock.toString`

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

`LocalUtf8StringValueBlock.blockName`
