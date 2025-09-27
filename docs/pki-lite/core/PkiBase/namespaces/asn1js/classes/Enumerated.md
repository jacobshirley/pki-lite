[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / Enumerated

# Class: Enumerated

## Extends

- [`Integer`](Integer.md)

## Constructors

### Constructor

> **new Enumerated**(`parameters?`): `Enumerated`

#### Parameters

##### parameters?

[`IntegerParams`](../interfaces/IntegerParams.md)

#### Returns

`Enumerated`

#### Overrides

[`Integer`](Integer.md).[`constructor`](Integer.md#constructor)

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

[`Integer`](Integer.md).[`blockLength`](Integer.md#blocklength)

---

### error

> **error**: `string`

#### Inherited from

[`Integer`](Integer.md).[`error`](Integer.md#error)

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

[`Integer`](Integer.md).[`idBlock`](Integer.md#idblock)

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

[`Integer`](Integer.md).[`lenBlock`](Integer.md#lenblock)

---

### name

> **name**: `string`

#### Inherited from

[`Integer`](Integer.md).[`name`](Integer.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`Integer`](Integer.md).[`optional`](Integer.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`Integer`](Integer.md).[`primitiveSchema`](Integer.md#primitiveschema)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

[`Integer`](Integer.md).[`valueBeforeDecodeView`](Integer.md#valuebeforedecodeview)

---

### valueBlock

> **valueBlock**: `LocalIntegerValueBlock`

#### Inherited from

[`Integer`](Integer.md).[`valueBlock`](Integer.md#valueblock)

---

### warnings

> **warnings**: `string`[]

#### Inherited from

[`Integer`](Integer.md).[`warnings`](Integer.md#warnings)

---

### NAME

> `static` **NAME**: `string`

Name of the block

#### Overrides

[`Integer`](Integer.md).[`NAME`](Integer.md#name-1)

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

[`Integer`](Integer.md).[`valueBeforeDecode`](Integer.md#valuebeforedecode)

## Methods

### convertFromDER()

> **convertFromDER**(): [`Integer`](Integer.md)

Convert current Integer value from DER to BER format

#### Returns

[`Integer`](Integer.md)

#### Inherited from

[`Integer`](Integer.md).[`convertFromDER`](Integer.md#convertfromder)

---

### convertToDER()

> **convertToDER**(): [`Integer`](Integer.md)

#### Returns

[`Integer`](Integer.md)

#### Inherited from

[`Integer`](Integer.md).[`convertToDER`](Integer.md#converttoder)

---

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

[`Integer`](Integer.md).[`fromBER`](Integer.md#fromber)

---

### isEqual()

> **isEqual**(`other`): `other is Enumerated`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is Enumerated`

#### Inherited from

[`Integer`](Integer.md).[`isEqual`](Integer.md#isequal)

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

[`Integer`](Integer.md).[`onAsciiEncoding`](Integer.md#onasciiencoding)

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

[`Integer`](Integer.md).[`toBER`](Integer.md#tober)

---

### toBigInt()

> **toBigInt**(): `bigint`

Converts Integer into BigInt

#### Returns

`bigint`

#### Throws

Throws Error if BigInt is not supported

#### Since

3.0.0

#### Inherited from

[`Integer`](Integer.md).[`toBigInt`](Integer.md#tobigint)

---

### toJSON()

> **toJSON**(): [`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalIntegerValueBlockJson`\>

Returns a JSON representation of an object

#### Returns

[`BaseBlockJson`](../interfaces/BaseBlockJson.md)\<`LocalIntegerValueBlockJson`\>

JSON object

#### Inherited from

[`Integer`](Integer.md).[`toJSON`](Integer.md#tojson)

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

[`Integer`](Integer.md).[`toString`](Integer.md#tostring)

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

[`Integer`](Integer.md).[`blockName`](Integer.md#blockname)

---

### fromBigInt()

> `static` **fromBigInt**(`value`): [`Integer`](Integer.md)

Creates Integer from BigInt value

#### Parameters

##### value

BigInt value

`string` | `number` | `bigint` | `boolean`

#### Returns

[`Integer`](Integer.md)

ASN.1 Integer

#### Throws

Throws Error if BigInt is not supported

#### Since

3.0.0

#### Inherited from

[`Integer`](Integer.md).[`fromBigInt`](Integer.md#frombigint)
