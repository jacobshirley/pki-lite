[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / base64ToArray

# Function: base64ToArray()

> **base64ToArray**(`base64`): `Uint8Array<ArrayBuffer>`

Converts a base64 string to a Uint8Array<ArrayBuffer> in a browser-compatible way.
Uses the atob() function available in both browsers and Node.js.

## Parameters

### base64

`string`

The base64 string to decode

## Returns

`Uint8Array<ArrayBuffer>`

The decoded bytes
