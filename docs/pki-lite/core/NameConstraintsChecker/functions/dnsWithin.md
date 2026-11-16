[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / dnsWithin

# Function: dnsWithin()

> **dnsWithin**(`name`, `constraint`): `boolean`

Whether the DNS name is the constraint or a subdomain of it (RFC 5280: "any DNS name
that can be constructed by simply adding zero or more labels to the left-hand side").
A constraint with a leading dot (".example.com") matches subdomains only.

## Parameters

### name

`string`

### constraint

`string`

## Returns

`boolean`
