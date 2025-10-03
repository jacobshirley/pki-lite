[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / UniversalString

# Class: UniversalString

## Extends

- `LocalUniversalStringValueBlock`

## Constructors

### Constructor

> **new UniversalString**(`__namedParameters?`): `UniversalString`

#### Parameters

##### \_\_namedParameters?

`LocalSimpleStringBlockParams`

#### Returns

`UniversalString`

#### Overrides

`LocalUniversalStringValueBlock.constructor`

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

`LocalUniversalStringValueBlock.blockLength`

---

### error

> **error**: `string`

#### Inherited from

`LocalUniversalStringValueBlock.error`

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

`LocalUniversalStringValueBlock.idBlock`

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

`LocalUniversalStringValueBlock.lenBlock`

---

### name

> **name**: `string`

#### Inherited from

`LocalUniversalStringValueBlock.name`

---

### optional

> **optional**: `boolean`

#### Inherited from

`LocalUniversalStringValueBlock.optional`

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

`LocalUniversalStringValueBlock.primitiveSchema`

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array<ArrayBuffer>`

#### Since

3.0.0

#### Inherited from

`LocalUniversalStringValueBlock.valueBeforeDecodeView`

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

`LocalUniversalStringValueBlock.valueBlock`

---

### warnings

> **warnings**: `string`[]

#### Inherited from

`LocalUniversalStringValueBlock.warnings`

---

### NAME

> `static` **NAME**: `string`

#### Overrides

`LocalUniversalStringValueBlock.NAME`

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

`LocalUniversalStringValueBlock.valueBeforeDecode`

## Methods

### fromBER()

> **fromBER**(`inputBuffer`, `inputOffset`, `inputLength`): `number`

#### Parameters

##### inputBuffer

`ArrayBuffer` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

##### inputOffset

`number`

##### inputLength

`number`

#### Returns

`number`

#### Inherited from

`LocalUniversalStringValueBlock.fromBER`

---

### fromBuffer()

> **fromBuffer**(`inputBuffer`): `void`

#### Parameters

##### inputBuffer

`ArrayBuffer` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

#### Returns

`void`

#### Inherited from

`LocalUniversalStringValueBlock.fromBuffer`

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Inherited from

`LocalUniversalStringValueBlock.fromString`

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

`LocalUniversalStringValueBlock.getValue`

---

### isEqual()

> **isEqual**(`other`): `other is UniversalString`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is UniversalString`

#### Inherited from

`LocalUniversalStringValueBlock.isEqual`

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

`LocalUniversalStringValueBlock.onAsciiEncoding`

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

`LocalUniversalStringValueBlock.setValue`

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

`LocalUniversalStringValueBlock.toBER`

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

JSON object

#### Inherited from

`LocalUniversalStringValueBlock.toJSON`

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

`LocalUniversalStringValueBlock.toString`

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

`LocalUniversalStringValueBlock.blockName`
