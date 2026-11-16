[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CrlChecker](../README.md) / CrlStatus

# Type Alias: CrlStatus

> **CrlStatus** = `object`

## Properties

### details

> **details**: `string`

---

### reason?

> `optional` **reason**: `number`

---

### revocationTime?

> `optional` **revocationTime**: `Date`

---

### status

> **status**: `"good"` \| `"revoked"` \| `"undetermined"`

good: not revoked by CRLs covering every reason; undetermined: no such CRLs
