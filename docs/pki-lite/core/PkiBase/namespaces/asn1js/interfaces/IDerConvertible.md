[**PKI-Lite v1.0.0**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / IDerConvertible

# Interface: IDerConvertible

## Methods

### fromDER()

> **fromDER**(`inputBuffer`, `inputOffset`, `inputLength`, `expectedLength?`): `number`

Base function for converting block from DER encoded array of bytes

#### Parameters

##### inputBuffer

`ArrayBuffer`

ASN.1 DER encoded array

##### inputOffset

`number`

Offset in ASN.1 DER encoded array where decoding should be started

##### inputLength

`number`

Maximum length of array of bytes which can be using in this function

##### expectedLength?

`number`

Expected length of converted VALUE_HEX buffer

#### Returns

`number`

Offset after least decoded byte

---

### toDER()

> **toDER**(`sizeOnly?`): `ArrayBuffer`

Encoding of current ASN.1 block into ASN.1 encoded array (DER rules)

#### Parameters

##### sizeOnly?

`boolean`

Flag that we need only a size of encoding, not a real array of bytes

#### Returns

`ArrayBuffer`

ASN.1 DER encoded array
