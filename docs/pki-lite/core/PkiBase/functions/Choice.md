[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / Choice

# Function: Choice()

> **Choice**\<`T`\>(`name`, `choices`): `T`

Creates a choice type for ASN.1 CHOICE constructs.
This is a helper function for creating discriminated union types.

## Type Parameters

### T

`T`

The choice type

## Parameters

### name

`string`

The name of the choice for debugging

### choices

`T`

The possible choice values

## Returns

`T`

The choice object with a custom toString tag
