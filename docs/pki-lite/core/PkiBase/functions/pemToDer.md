[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / pemToDer

# Function: pemToDer()

> **pemToDer**(`pem`, `name`): `Uint8Array`\<`ArrayBuffer`\>

Extracts DER-encoded data from a PEM-formatted string.
Supports multiple possible PEM header names for flexibility.

## Parameters

### pem

`string`

The PEM-formatted string

### name

The PEM header name(s) to look for (e.g., "CERTIFICATE")

`string` | `string`[]

## Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes

## Throws

Error if multiple PEM blocks are found or format is invalid
