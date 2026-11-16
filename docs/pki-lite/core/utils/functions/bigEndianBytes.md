[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/utils](../README.md) / bigEndianBytes

# Function: bigEndianBytes()

> **bigEndianBytes**(`value`): `Uint8Array`\<`ArrayBuffer`\>

Converts a non-negative integer to its minimal big-endian bytes (0 -> [0]), e.g. for
WebCrypto's publicExponent: 65537 -> [0x01, 0x00, 0x01].

## Parameters

### value

`number`

The integer to convert

## Returns

`Uint8Array`\<`ArrayBuffer`\>

The big-endian bytes
