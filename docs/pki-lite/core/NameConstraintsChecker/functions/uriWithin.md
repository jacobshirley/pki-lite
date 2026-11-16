[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / uriWithin

# Function: uriWithin()

> **uriWithin**(`uri`, `constraint`): `boolean`

URI constraint (RFC 5280 4.2.1.10): applies to the host part. "host.example.com"
matches that host only; ".example.com" matches hosts in any subdomain.

## Parameters

### uri

`string`

### constraint

`string`

## Returns

`boolean`
