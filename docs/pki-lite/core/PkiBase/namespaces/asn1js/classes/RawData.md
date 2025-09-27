[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / RawData

# Class: RawData

Special class providing ability to have "toBER/fromBER" for raw ArrayBuffer

## Implements

- [`IBerConvertible`](../interfaces/IBerConvertible.md)

## Constructors

### Constructor

> **new RawData**(`__namedParameters?`): `RawData`

#### Parameters

##### \_\_namedParameters?

`Partial`\<[`IRawData`](../interfaces/IRawData.md)\>

#### Returns

`RawData`

## Properties

### dataView

> **dataView**: `Uint8Array`

#### Since

3.0.0

## Accessors

### data

#### Get Signature

> **get** **data**(): `ArrayBuffer`

##### Deprecated

Since v3.0.0

##### Returns

`ArrayBuffer`

#### Set Signature

> **set** **data**(`value`): `void`

##### Deprecated

Since v3.0.0

##### Parameters

###### value

`ArrayBuffer`

##### Returns

`void`

## Methods

### fromBER()

> **fromBER**(`inputBuffer`, `inputOffset`, `inputLength`): `number`

Base function for converting block from BER encoded array of bytes

#### Parameters

##### inputBuffer

ASN.1 BER encoded array

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

##### inputOffset

`number`

Offset in ASN.1 BER encoded array where decoding should be started

##### inputLength

`number`

Maximum length of array of bytes which can be using in this function

#### Returns

`number`

Offset after least decoded byte

#### Implementation of

[`IBerConvertible`](../interfaces/IBerConvertible.md).[`fromBER`](../interfaces/IBerConvertible.md#fromber)

---

### toBER()

> **toBER**(`_sizeOnly?`): `ArrayBuffer`

Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)

#### Parameters

##### \_sizeOnly?

`boolean`

Flag that we need only a size of encoding, not a real array of bytes

#### Returns

`ArrayBuffer`

ASN.1 BER encoded array

#### Implementation of

[`IBerConvertible`](../interfaces/IBerConvertible.md).[`toBER`](../interfaces/IBerConvertible.md#tober)
