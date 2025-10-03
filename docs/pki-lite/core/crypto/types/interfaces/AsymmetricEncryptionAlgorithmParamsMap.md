[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/types](../README.md) / AsymmetricEncryptionAlgorithmParamsMap

# Interface: AsymmetricEncryptionAlgorithmParamsMap

Parameter mapping for asymmetric encryption and signature algorithms.
Each algorithm type has its own specific parameter requirements.

## Properties

### ECDH

> **ECDH**: `object`

Elliptic Curve Diffie-Hellman parameters.

#### namedCurve

> **namedCurve**: [`NamedCurve`](../type-aliases/NamedCurve.md)

Named curve identifier

---

### ECDSA

> **ECDSA**: `object`

Elliptic Curve Digital Signature Algorithm parameters.

#### hash

> **hash**: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Hash algorithm for signature

#### namedCurve

> **namedCurve**: [`NamedCurve`](../type-aliases/NamedCurve.md)

Named curve identifier

---

### RSA_OAEP

> **RSA_OAEP**: `object`

RSA Optimal Asymmetric Encryption Padding (OAEP) parameters.

#### hash

> **hash**: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Hash algorithm for mask generation

#### label?

> `optional` **label**: `Uint8Array`\<`ArrayBuffer`\>

Optional label for encryption

#### pSourceAlgorithm?

> `optional` **pSourceAlgorithm**: `string`

Mask generation function algorithm

---

### RSA_PSS

> **RSA_PSS**: `object`

RSA Probabilistic Signature Scheme (PSS) parameters.

#### hash

> **hash**: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Hash algorithm for signature generation

#### saltLength

> **saltLength**: `number`

Salt length in bytes

---

### RSASSA_PKCS1_v1_5

> **RSASSA_PKCS1_v1_5**: `object`

RSA PKCS#1 v1.5 signature parameters.

#### hash

> **hash**: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Hash algorithm for signature
