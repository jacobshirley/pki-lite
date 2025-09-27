[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/types](../README.md) / DerivationAlgorithmParamsMap

# Interface: DerivationAlgorithmParamsMap

Parameter mapping for key derivation algorithms.

## Properties

### PBKDF2

> **PBKDF2**: `object`

Password-Based Key Derivation Function 2 parameters.

#### hash

> **hash**: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### keyLength?

> `optional` **keyLength**: `number`

Desired key length in bytes (optional)

#### salt

> **salt**: `Uint8Array`

Salt value for key derivation
