[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / ipWithin

# Function: ipWithin()

> **ipWithin**(`ip`, `constraint`): `boolean`

iPAddress constraint: an address followed by a mask (8 bytes for IPv4, 32 for IPv6).
The name matches when it is the same family and equal to the address under the mask.

## Parameters

### ip

`Uint8Array`

### constraint

`Uint8Array`

## Returns

`boolean`
