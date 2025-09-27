[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / CertificateChain

# Interface: CertificateChain

Certificate chain information.

## Properties

### certificates

> **certificates**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

Certificates in the chain from end-entity to root

---

### isComplete

> **isComplete**: `boolean`

Whether the chain was successfully built

---

### trustAnchor?

> `optional` **trustAnchor**: [`TrustAnchor`](TrustAnchor.md)

Trust anchor used (if any)
