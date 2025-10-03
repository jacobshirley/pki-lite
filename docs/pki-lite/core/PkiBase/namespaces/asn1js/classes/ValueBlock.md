[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / ValueBlock

# Class: ValueBlock

## Extends

- `LocalBaseBlock`

## Implements

- [`IValueBlock`](../type-aliases/IValueBlock.md)
- [`IBerConvertible`](../interfaces/IBerConvertible.md)

## Constructors

### Constructor

> **new ValueBlock**(`param0?`): `ValueBlock`

Creates and initializes an object instance of that class

#### Parameters

##### param0?

`LocalBaseBlockParams`

Initialization parameters

#### Returns

`ValueBlock`

#### Inherited from

`LocalBaseBlock.constructor`

## Properties

### blockLength

> **blockLength**: `number`

#### Implementation of

`IValueBlock.blockLength`

#### Inherited from

`LocalBaseBlock.blockLength`

---

### error

> **error**: `string`

#### Implementation of

`IValueBlock.error`

#### Inherited from

`LocalBaseBlock.error`

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array<ArrayBuffer>`

#### Since

3.0.0

#### Inherited from

`LocalBaseBlock.valueBeforeDecodeView`

---

### warnings

> **warnings**: `string`[]

#### Implementation of

`IValueBlock.warnings`

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

> **fromBER**(`_inputBuffer`, `_inputOffset`, `_inputLength`): `number`

Base function for converting block from BER encoded array of bytes

#### Parameters

##### \_inputBuffer

ASN.1 BER encoded array

`ArrayBuffer` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

##### \_inputOffset

`number`

Offset in ASN.1 BER encoded array where decoding should be started

##### \_inputLength

`number`

Maximum length of array of bytes which can be using in this function

#### Returns

`number`

Offset after least decoded byte

#### Implementation of

[`IBerConvertible`](../interfaces/IBerConvertible.md).[`fromBER`](../interfaces/IBerConvertible.md#fromber)

---

### toBER()

> **toBER**(`_sizeOnly?`, `_writer?`): `ArrayBuffer`

Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)

#### Parameters

##### \_sizeOnly?

`boolean`

Flag that we need only a size of encoding, not a real array of bytes

##### \_writer?

[`ViewWriter`](ViewWriter.md)

#### Returns

`ArrayBuffer`

ASN.1 BER encoded array

#### Implementation of

[`IBerConvertible`](../interfaces/IBerConvertible.md).[`toBER`](../interfaces/IBerConvertible.md#tober)

---

### toJSON()

> **toJSON**(): `LocalBaseBlockJson`

Returns a JSON representation of an object

#### Returns

`LocalBaseBlockJson`

JSON object

#### Inherited from

`LocalBaseBlock.toJSON`

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

`LocalBaseBlock.blockName`
