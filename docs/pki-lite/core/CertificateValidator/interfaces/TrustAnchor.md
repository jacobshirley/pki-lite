[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / TrustAnchor

# Interface: TrustAnchor

Trust anchor for certificate validation.

## Properties

### certificate

> **certificate**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)

The trusted root certificate

---

### nameConstraints?

> `optional` **nameConstraints**: [`NameConstraints`](../../../x509/extensions/NameConstraints/classes/NameConstraints.md)

Optional name constraints to apply to every certificate below this trust anchor,
in addition to any in the trust anchor's own certificate (when validating name
constraints).
