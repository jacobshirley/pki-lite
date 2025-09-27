[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / GeneralizedTime

# Class: GeneralizedTime

## Extends

- [`UTCTime`](UTCTime.md)

## Constructors

### Constructor

> **new GeneralizedTime**(`parameters?`): `GeneralizedTime`

#### Parameters

##### parameters?

[`UTCTimeParams`](../interfaces/UTCTimeParams.md)

#### Returns

`GeneralizedTime`

#### Overrides

[`UTCTime`](UTCTime.md).[`constructor`](UTCTime.md#constructor)

## Properties

### blockLength

> **blockLength**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`blockLength`](UTCTime.md#blocklength)

---

### day

> **day**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`day`](UTCTime.md#day)

---

### error

> **error**: `string`

#### Inherited from

[`UTCTime`](UTCTime.md).[`error`](UTCTime.md#error)

---

### hour

> **hour**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`hour`](UTCTime.md#hour)

---

### idBlock

> **idBlock**: `LocalIdentificationBlock`

#### Inherited from

[`UTCTime`](UTCTime.md).[`idBlock`](UTCTime.md#idblock)

---

### lenBlock

> **lenBlock**: `LocalLengthBlock`

#### Inherited from

[`UTCTime`](UTCTime.md).[`lenBlock`](UTCTime.md#lenblock)

---

### millisecond

> **millisecond**: `number`

---

### minute

> **minute**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`minute`](UTCTime.md#minute)

---

### month

> **month**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`month`](UTCTime.md#month)

---

### name

> **name**: `string`

#### Inherited from

[`UTCTime`](UTCTime.md).[`name`](UTCTime.md#name)

---

### optional

> **optional**: `boolean`

#### Inherited from

[`UTCTime`](UTCTime.md).[`optional`](UTCTime.md#optional)

---

### primitiveSchema?

> `optional` **primitiveSchema**: [`BaseBlock`](BaseBlock.md)\<[`ValueBlock`](ValueBlock.md), `LocalBaseBlockJson`\>

#### Inherited from

[`UTCTime`](UTCTime.md).[`primitiveSchema`](UTCTime.md#primitiveschema)

---

### second

> **second**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`second`](UTCTime.md#second)

---

### valueBeforeDecodeView

> **valueBeforeDecodeView**: `Uint8Array`

#### Since

3.0.0

#### Inherited from

[`UTCTime`](UTCTime.md).[`valueBeforeDecodeView`](UTCTime.md#valuebeforedecodeview)

---

### valueBlock

> **valueBlock**: `LocalSimpleStringValueBlock`

#### Inherited from

[`UTCTime`](UTCTime.md).[`valueBlock`](UTCTime.md#valueblock)

---

### warnings

> **warnings**: `string`[]

#### Inherited from

[`UTCTime`](UTCTime.md).[`warnings`](UTCTime.md#warnings)

---

### year

> **year**: `number`

#### Inherited from

[`UTCTime`](UTCTime.md).[`year`](UTCTime.md#year)

---

### NAME

> `static` **NAME**: `string`

#### Overrides

[`UTCTime`](UTCTime.md).[`NAME`](UTCTime.md#name-1)

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

[`UTCTime`](UTCTime.md).[`valueBeforeDecode`](UTCTime.md#valuebeforedecode)

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

[`UTCTime`](UTCTime.md).[`fromBER`](UTCTime.md#fromber)

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

[`UTCTime`](UTCTime.md).[`fromBuffer`](UTCTime.md#frombuffer)

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

#### Overrides

[`UTCTime`](UTCTime.md).[`fromDate`](UTCTime.md#fromdate)

---

### fromString()

> **fromString**(`inputString`): `void`

#### Parameters

##### inputString

`string`

#### Returns

`void`

#### Overrides

[`UTCTime`](UTCTime.md).[`fromString`](UTCTime.md#fromstring)

---

### getValue()

> **getValue**(): `string`

String value

#### Returns

`string`

#### Since

3.0.0

#### Inherited from

[`UTCTime`](UTCTime.md).[`getValue`](UTCTime.md#getvalue)

---

### isEqual()

> **isEqual**(`other`): `other is GeneralizedTime`

Determines whether two object instances are equal

#### Parameters

##### other

`unknown`

Object to compare with the current object

#### Returns

`other is GeneralizedTime`

#### Inherited from

[`UTCTime`](UTCTime.md).[`isEqual`](UTCTime.md#isequal)

---

### onAsciiEncoding()

> `protected` **onAsciiEncoding**(): `string`

#### Returns

`string`

#### Inherited from

[`UTCTime`](UTCTime.md).[`onAsciiEncoding`](UTCTime.md#onasciiencoding)

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

[`UTCTime`](UTCTime.md).[`setValue`](UTCTime.md#setvalue)

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

[`UTCTime`](UTCTime.md).[`toBER`](UTCTime.md#tober)

---

### toBuffer()

> **toBuffer**(): `ArrayBuffer`

Function converting ASN.1 internal string into ArrayBuffer

#### Returns

`ArrayBuffer`

#### Inherited from

[`UTCTime`](UTCTime.md).[`toBuffer`](UTCTime.md#tobuffer)

---

### toDate()

> **toDate**(): `Date`

Converts a class object into the JavaScrip Date Object

#### Returns

`Date`

Date object

#### Overrides

[`UTCTime`](UTCTime.md).[`toDate`](UTCTime.md#todate)

---

### toJSON()

> **toJSON**(): [`GeneralizedTimeJson`](../interfaces/GeneralizedTimeJson.md)

Returns a JSON representation of an object

#### Returns

[`GeneralizedTimeJson`](../interfaces/GeneralizedTimeJson.md)

JSON object

#### Overrides

[`UTCTime`](UTCTime.md).[`toJSON`](UTCTime.md#tojson)

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

[`UTCTime`](UTCTime.md).[`toString`](UTCTime.md#tostring)

---

### blockName()

> `static` **blockName**(): `string`

Aux function, need to get a block name. Need to have it here for inheritance

#### Returns

`string`

Returns name of the block

#### Inherited from

[`UTCTime`](UTCTime.md).[`blockName`](UTCTime.md#blockname)
