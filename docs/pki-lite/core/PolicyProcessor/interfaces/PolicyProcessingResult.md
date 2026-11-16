[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PolicyProcessor](../README.md) / PolicyProcessingResult

# Interface: PolicyProcessingResult

## Properties

### isValid

> **isValid**: `boolean`

whether path processing succeeded (RFC 5280 6.1.5 (g))

---

### validPolicies

> **validPolicies**: `string`[]

the user-constrained policy set: the policies valid for the whole path, as policies
of the trust anchor's domain (that of the initial policy set, before any policy
mappings)

---

### violations

> **violations**: `string`[]

why processing failed
