[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CrlChecker](../README.md) / CrlCheckerOptions

# Type Alias: CrlCheckerOptions

> **CrlCheckerOptions** = `object`

## Properties

### certificates

> **certificates**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

Every certificate available to find CRL signers among (path, extras, anchors)

---

### crls

> **crls**: [`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md)[]

The CRLs available

---

### strictProfile?

> `optional` **strictProfile**: `boolean`

Also require the RFC 5280 CRL profile (section 5): a cRLNumber extension, not
critical (5.2.3), and no certificate listed twice.

---

### time

> **time**: `Date`

The time to check at

---

### trustAnchors

> **trustAnchors**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

Trust anchor certificates: trusted as CRL signers without a path

---

### validateSigner()

> **validateSigner**: (`signer`) => `Promise`\<`boolean`\>

Validates the certification path of a CRL signer that is not a trust anchor,
including its own revocation status (RFC 5280 6.3.3 (f)).

#### Parameters

##### signer

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

#### Returns

`Promise`\<`boolean`\>
