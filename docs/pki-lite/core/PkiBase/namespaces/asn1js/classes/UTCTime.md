[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / UTCTime

# Class: UTCTime

## Extends

- [`VisibleString`](VisibleString.md)

## Extended by

- [`GeneralizedTime`](GeneralizedTime.md)

## Implements

- [`IUTCTime`](../interfaces/IUTCTime.md)
- [`IDateConvertible`](../interfaces/IDateConvertible.md)

## Constructors

### Constructor

> **new UTCTime**(`__namedParameters?`): `UTCTime`

#### Parameters

##### \_\_namedParameters?

[`UTCTimeParams`](../interfaces/UTCTimeParams.md)

#### Returns

`UTCTime`

#### Overrides

[`VisibleString`](VisibleString.md).[`constructor`](VisibleString.md#constructor)

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

[`VisibleString`](VisibleString.md).[`blockLength`](VisibleString.md#blocklength)

---

### day

> **day**: `number`

#### Implementation of

[`IUTCTime`](../interfaces/IUTCTime.md).[`day`](../interfaces/IUTCTime.md#day)

---

### error

> **error**: `string`

#### Inherited from

[`VisibleString`](VisibleString.md).[`error`](VisibleString.md#error)

---

### hour

> **hour**: `number`

#### Implementation of

[`IUTCTime`](../interfaces/IUTCTime.md).[`hour`](../interfaces/IUTCTime.md#hour)

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

[`VisibleString`](VisibleString.md).[`idBlock`](VisibleString.md#idblock)

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

[`VisibleString`](VisibleString.md).[`lenBlock`](VisibleString.md#lenblock)

---

### minute

> **minute**: `number`

#### Implementation of

[`IUTCTime`](../interfaces/IUTCTime.md).[`minute`](../interfaces/IUTCTime.md#minute)

---

### month

> **month**: `number`

#### Implementation of

[`IUTCTime`](../interfaces/IUTCTime.md).[`month`](../interfaces/IUTCTime.md#month)

---

### name

> **name**: `string`

#### Inherited from

[`VisibleString`](VisibleString.md).[`name`](VisibleString.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`VisibleString`](VisibleString.md).[`optional`](VisibleString.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`VisibleString`](VisibleString.md).[`primitiveSchema`](VisibleString.md#primitiveschema)

---

### second

> **second**: `number`

#### Implementation of

[`IUTCTime`](../interfaces/IUTCTime.md).[`second`](../interfaces/IUTCTime.md#second)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

[`VisibleString`](VisibleString.md).[`valueBeforeDecodeView`](VisibleString.md#valuebeforedecodeview)

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

[`VisibleString`](VisibleString.md).[`valueBlock`](VisibleString.md#valueblock)

---

### warnings

> **warnings**: `string`[]

#### Inherited from

[`VisibleString`](VisibleString.md).[`warnings`](VisibleString.md#warnings)

---

### year

> **year**: `number`

#### Implementation of

[`IUTCTime`](../interfaces/IUTCTime.md).[`year`](../interfaces/IUTCTime.md#year)

---

### NAME

> `static` **NAME**: `string`

#### Overrides

[`VisibleString`](VisibleString.md).[`NAME`](VisibleString.md#name-1)

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

[`VisibleString`](VisibleString.md).[`valueBeforeDecode`](VisibleString.md#valuebeforedecode)

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

[`VisibleString`](VisibleString.md).[`fromBER`](VisibleString.md#fromber)

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

#### Overrides

[`VisibleString`](VisibleString.md).[`fromBuffer`](VisibleString.md#frombuffer)

---

### fromDate()

> **fromDate**(`inputDate`): `void`

Function converting "Date" object into ASN.1 internal string

#### Parameters

##### inputDate

`Date`

JavaScript "Date" object

#### Returns

`void`

#### Implementation of

[`IDateConvertible`](../interfaces/IDateConvertible.md).[`fromDate`](../interfaces/IDateConvertible.md#fromdate)

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Overrides

[`VisibleString`](VisibleString.md).[`fromString`](VisibleString.md#fromstring)

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

[`VisibleString`](VisibleString.md).[`getValue`](VisibleString.md#getvalue)

---

### isEqual()

> **isEqual**(`other`): `other is UTCTime`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is UTCTime`

#### Inherited from

[`VisibleString`](VisibleString.md).[`isEqual`](VisibleString.md#isequal)

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Overrides

[`VisibleString`](VisibleString.md).[`onAsciiEncoding`](VisibleString.md#onasciiencoding)

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

[`VisibleString`](VisibleString.md).[`setValue`](VisibleString.md#setvalue)

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

[`VisibleString`](VisibleString.md).[`toBER`](VisibleString.md#tober)

---

### toBuffer()

> **toBuffer**(): `ArrayBuffer`

Function converting ASN.1 internal string into ArrayBuffer

#### Returns

`ArrayBuffer`

---

### toDate()

> **toDate**(): `Date`

Converts a class object into the JavaScrip Date Object

#### Returns

`Date`

Date object

#### Implementation of

[`IDateConvertible`](../interfaces/IDateConvertible.md).[`toDate`](../interfaces/IDateConvertible.md#todate)

---

### toJSON()

> **toJSON**(): [`UTCTimeJson`](../interfaces/UTCTimeJson.md)

Returns a JSON representation of an object

#### Returns

[`UTCTimeJson`](../interfaces/UTCTimeJson.md)

JSON object

#### Overrides

[`VisibleString`](VisibleString.md).[`toJSON`](VisibleString.md#tojson)

---

### toString()

> **toString**(`encoding?`): `string`

Returns a string representation of an object.

#### Parameters

##### encoding?

[`DateStringEncoding`](../type-aliases/DateStringEncoding.md)

#### Returns

`string`

#### Overrides

[`VisibleString`](VisibleString.md).[`toString`](VisibleString.md#tostring)

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

[`VisibleString`](VisibleString.md).[`blockName`](VisibleString.md#blockname)
