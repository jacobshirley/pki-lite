[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / GeneralString

# Class: GeneralString

## Extends

- `LocalSimpleStringBlock`

## Constructors

### Constructor

> **new GeneralString**(`parameters?`): `GeneralString`

#### Parameters

##### parameters?

`LocalSimpleStringBlockParams`

#### Returns

`GeneralString`

#### Overrides

`LocalSimpleStringBlock.constructor`

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

`LocalSimpleStringBlock.blockLength`

---

### error

> **error**: `string`

#### Inherited from

`LocalSimpleStringBlock.error`

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

`LocalSimpleStringBlock.idBlock`

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

`LocalSimpleStringBlock.lenBlock`

---

### name

> **name**: `string`

#### Inherited from

`LocalSimpleStringBlock.name`

---

### optional

> **optional**: `boolean`

#### Inherited from

`LocalSimpleStringBlock.optional`

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

`LocalSimpleStringBlock.primitiveSchema`

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

`LocalSimpleStringBlock.valueBeforeDecodeView`

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

`LocalSimpleStringBlock.valueBlock`

---

### warnings

> **warnings**: `string`[]

#### Inherited from

`LocalSimpleStringBlock.warnings`

---

### NAME

> `static` **NAME**: `string`

#### Overrides

`LocalSimpleStringBlock.NAME`

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

`LocalSimpleStringBlock.valueBeforeDecode`

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

`LocalSimpleStringBlock.fromBER`

---

### fromBuffer()

> **fromBuffer**(`inputBuffer`): `void`

Function converting ArrayBuffer into ASN.1 internal string

#### Parameters

##### inputBuffer

ASN.1 BER encoded array

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`void`

#### Inherited from

`LocalSimpleStringBlock.fromBuffer`

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Inherited from

`LocalSimpleStringBlock.fromString`

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

`LocalSimpleStringBlock.getValue`

---

### isEqual()

> **isEqual**(`other`): `other is GeneralString`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is GeneralString`

#### Inherited from

`LocalSimpleStringBlock.isEqual`

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

`LocalSimpleStringBlock.onAsciiEncoding`

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

`LocalSimpleStringBlock.setValue`

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

`LocalSimpleStringBlock.toBER`

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

JSON object

#### Inherited from

`LocalSimpleStringBlock.toJSON`

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

`LocalSimpleStringBlock.toString`

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

`LocalSimpleStringBlock.blockName`
