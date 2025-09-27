[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / RevocationStatus

# Interface: RevocationStatus

Represents the revocation status of a certificate.

## Properties

### details?

> `optional` **details**: `string`

Additional information about the revocation check

---

### isRevoked

> **isRevoked**: `boolean`

Whether the certificate is revoked

---

### reason?

> `optional` **reason**: `number`

The reason for revocation, if available

---

### revocationTime?

> `optional` **revocationTime**: `Date`

The date when revocation was determined

---

### source

> **source**: `"OCSP"` \| `"CRL"` \| `"NONE"`

The source of revocation information (CRL or OCSP)
