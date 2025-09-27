[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/SignedDataBuilder](../README.md) / SignedDataBuilderSigner

# Type Alias: SignedDataBuilderSigner

> **SignedDataBuilderSigner** = `object`

Configuration for a signer in the SignedData structure.

## Properties

### certificate

> **certificate**: [`CertificateChoices`](../../../../x509/CertificateChoices/type-aliases/CertificateChoices.md)

The signer's certificate.

---

### encryptionAlgorithm?

> `optional` **encryptionAlgorithm**: [`AsymmetricEncryptionAlgorithmParams`](../../../crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Optional encryption algorithm parameters.

---

### privateKeyInfo

> **privateKeyInfo**: [`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The private key used for signing.

---

### signedAttrs?

> `optional` **signedAttrs**: [`Attribute`](../../../../x509/Attribute/classes/Attribute.md)[]

Optional signed attributes to include in the signature.

---

### tsa?

> `optional` **tsa**: `true` \| \{ `hash?`: [`HashAlgorithm`](../../../crypto/types/type-aliases/HashAlgorithm.md); `password?`: `string`; `policyId?`: `string`; `url`: `string`; `username?`: `string`; \}

Optional timestamp authority configuration for timestamping.

---

### unsignedAttrs?

> `optional` **unsignedAttrs**: [`Attribute`](../../../../x509/Attribute/classes/Attribute.md)[]

Optional unsigned attributes (e.g., countersignatures).
