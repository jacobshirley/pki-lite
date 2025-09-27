[**PKI-Lite**](../../../../../../README.md)

---

[PKI-Lite](../../../../../../README.md) / [pki-lite](../../../../../README.md) / [core/PkiBase](../../../README.md) / [asn1js](../README.md) / IBerConvertible

# Interface: IBerConvertible

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

---

### toBER()

> **toBER**(`sizeOnly?`): `ArrayBuffer`

Encoding of current ASN.1 block into ASN.1 encoded array (BER rules)

#### Parameters

##### sizeOnly?

`boolean`

Flag that we need only a size of encoding, not a real array of bytes

#### Returns

`ArrayBuffer`

ASN.1 BER encoded array
