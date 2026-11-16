[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / normalizeHost

# Function: normalizeHost()

> **normalizeHost**(`value`): `string`

A host name in comparable form: lower case, no trailing dot, internationalised labels
as A-labels ("bücher.example" -> "xn--bcher-kva.example", RFC 5280 7.2), so that U-label
and A-label spellings of a name compare equal. Leading "." or "\*." prefixes are kept.

## Parameters

### value

`string`

## Returns

`string`
