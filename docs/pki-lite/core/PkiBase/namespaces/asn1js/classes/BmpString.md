[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / BmpString

# Class: BmpString

## Extends

- `LocalBmpStringValueBlock`

## Constructors

### Constructor

> **new BmpString**(`__namedParameters?`): `BmpString`

#### Parameters

##### \_\_namedParameters?

`LocalSimpleStringBlockParams`

#### Returns

`BmpString`

#### Overrides

`LocalBmpStringValueBlock.constructor`

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

`LocalBmpStringValueBlock.blockLength`

---

### error

> **error**: `string`

#### Inherited from

`LocalBmpStringValueBlock.error`

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

`LocalBmpStringValueBlock.idBlock`

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

`LocalBmpStringValueBlock.lenBlock`

---

### name

> **name**: `string`

#### Inherited from

`LocalBmpStringValueBlock.name`

---

### optional

> **optional**: `boolean`

#### Inherited from

`LocalBmpStringValueBlock.optional`

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

`LocalBmpStringValueBlock.primitiveSchema`

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array<ArrayBuffer>`

#### Since

3.0.0

#### Inherited from

`LocalBmpStringValueBlock.valueBeforeDecodeView`

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

`LocalBmpStringValueBlock.valueBlock`

---

### warnings

> **warnings**: `string`[]

#### Inherited from

`LocalBmpStringValueBlock.warnings`

---

### NAME

> `static` **NAME**: `string`

#### Overrides

`LocalBmpStringValueBlock.NAME`

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

`LocalBmpStringValueBlock.valueBeforeDecode`

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

`LocalBmpStringValueBlock.fromBER`

---

### fromBuffer()

> **fromBuffer**(`inputBuffer`): `void`

#### Parameters

##### inputBuffer

`ArrayBuffer` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

#### Returns

`void`

#### Inherited from

`LocalBmpStringValueBlock.fromBuffer`

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Inherited from

`LocalBmpStringValueBlock.fromString`

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

`LocalBmpStringValueBlock.getValue`

---

### isEqual()

> **isEqual**(`other`): `other is BmpString`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is BmpString`

#### Inherited from

`LocalBmpStringValueBlock.isEqual`

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

`LocalBmpStringValueBlock.onAsciiEncoding`

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

`LocalBmpStringValueBlock.setValue`

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

`LocalBmpStringValueBlock.toBER`

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalStringValueBlockJson`\>

JSON object

#### Inherited from

`LocalBmpStringValueBlock.toJSON`

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

`LocalBmpStringValueBlock.toString`

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

`LocalBmpStringValueBlock.blockName`
