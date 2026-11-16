[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PolicyProcessor](../README.md) / PolicyProcessingOptions

# Interface: PolicyProcessingOptions

Inputs of the RFC 5280 6.1.1 certificate policy processing

## Properties

### initialAnyPolicyInhibit?

> `optional` **initialAnyPolicyInhibit**: `boolean`

initial-any-policy-inhibit: anyPolicy is not considered a match

---

### initialExplicitPolicy?

> `optional` **initialExplicitPolicy**: `boolean`

initial-explicit-policy: an acceptable policy is required in every case

---

### initialPolicyMappingInhibit?

> `optional` **initialPolicyMappingInhibit**: `boolean`

initial-policy-mapping-inhibit: policy mapping is not allowed

---

### initialPolicySet?

> `optional` **initialPolicySet**: `string`[]

user-initial-policy-set: acceptable policies (default: any policy)
