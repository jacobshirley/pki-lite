[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / arrayToBase64

# Function: arrayToBase64()

> **arrayToBase64**(`bytes`): `string`

Converts a Uint8Array<ArrayBuffer> to a base64 string in a browser-compatible way.
Uses the btoa() function available in both browsers and Node.js.

## Parameters

### bytes

`Uint8Array`\<`ArrayBuffer`\>

The bytes to encode

## Returns

`string`

The base64-encoded string
