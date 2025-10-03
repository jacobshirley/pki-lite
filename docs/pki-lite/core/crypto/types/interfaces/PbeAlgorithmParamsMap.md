[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/types](../README.md) / PbeAlgorithmParamsMap

# Interface: PbeAlgorithmParamsMap

Parameter mapping for password-based encryption algorithms.

## Extended by

- [`SymmetricEncryptionAlgorithmParamsMap`](SymmetricEncryptionAlgorithmParamsMap.md)

## Properties

### PBES2

> **PBES2**: `object`

Password-Based Encryption Scheme 2 parameters.

#### derivationAlgorithm

> **derivationAlgorithm**: `object`

Key derivation algorithm and parameters

##### derivationAlgorithm.params

> **params**: `object`

##### derivationAlgorithm.params.hash

> **hash**: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

##### derivationAlgorithm.params.iterationCount

> **iterationCount**: `number`

Number of iterations

##### derivationAlgorithm.params.keyLength?

> `optional` **keyLength**: `number`

Desired key length in bytes (optional)

##### derivationAlgorithm.params.salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

##### derivationAlgorithm.type

> **type**: `"PBKDF2"`

#### encryptionAlgorithm

> **encryptionAlgorithm**: [`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm and parameters
