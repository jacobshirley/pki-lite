[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / CertificateValidationOptions

# Interface: CertificateValidationOptions

Options for certificate validation.

## Properties

### checkCRL?

> `optional` **checkCRL**: `boolean`

Check certificate revocation using CRLs

---

### checkOCSP?

> `optional` **checkOCSP**: `boolean`

Check certificate revocation using OCSP

---

### checkSignature?

> `optional` **checkSignature**: `boolean`

Whether to perform signature validation

---

### enforceCAConstraints?

> `optional` **enforceCAConstraints**: `boolean`

Whether to enforce CA constraints and key usage

---

### otherCertificates?

> `optional` **otherCertificates**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

Other certificates available for chain building

---

### requiredPolicies?

> `optional` **requiredPolicies**: `string`[]

Required policy OIDs (if any)

---

### timeTolerance?

> `optional` **timeTolerance**: `number`

Tolerance for time-based validations (in milliseconds)

---

### trustAnchors?

> `optional` **trustAnchors**: [`TrustAnchor`](TrustAnchor.md)[]

Trust anchors to use for chain validation

---

### validateChain?

> `optional` **validateChain**: `boolean`

Whether to build and validate the full certificate chain

---

### validateNameConstraints?

> `optional` **validateNameConstraints**: `boolean`

Whether to validate name constraints

---

### validatePolicies?

> `optional` **validatePolicies**: `boolean`

Whether to validate certificate policies

---

### validationTime?

> `optional` **validationTime**: `Date`

Custom validation date (defaults to current time)
