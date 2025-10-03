[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/utils](../README.md) / padUint8Array

# Function: padUint8Array()

> **padUint8Array**(`array`, `targetLength`): `Uint8Array`\<`ArrayBuffer`\>

Pads a Uint8Array<ArrayBuffer> to the specified length by adding zeros to the left.
If the array is already at or exceeds the target length, it is returned as-is.

## Parameters

### array

`Uint8Array`\<`ArrayBuffer`\>

The array to pad

### targetLength

`number`

The desired length

## Returns

`Uint8Array`\<`ArrayBuffer`\>

A new Uint8Array padded to the target length
