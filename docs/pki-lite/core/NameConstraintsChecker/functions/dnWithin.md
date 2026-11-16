[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / dnWithin

# Function: dnWithin()

> **dnWithin**(`name`, `constraint`): `boolean`

directoryName constraint: the constraint's RDNs must match the first RDNs of the name
(RFC 5280 7.1 matching). The same as `name.isWithin(constraint)`.

## Parameters

### name

[`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

### constraint

[`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

## Returns

`boolean`
