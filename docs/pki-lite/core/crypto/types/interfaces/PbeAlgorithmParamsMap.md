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

---

### PKCS12_SHA1_3DES_2KEY

> **PKCS12_SHA1_3DES_2KEY**: `object`

PKCS#12 PBE with SHA-1 and 2-key Triple DES-CBC.

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

---

### PKCS12_SHA1_3DES_3KEY

> **PKCS12_SHA1_3DES_3KEY**: `object`

PKCS#12 PBE with SHA-1 and 3-key Triple DES-CBC.

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

---

### PKCS12_SHA1_RC2_128

> **PKCS12_SHA1_RC2_128**: `object`

PKCS#12 PBE with SHA-1 and 128-bit RC2-CBC.

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

---

### PKCS12_SHA1_RC2_40

> **PKCS12_SHA1_RC2_40**: `object`

PKCS#12 PBE with SHA-1 and 40-bit RC2-CBC.

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

---

### PKCS12_SHA1_RC4_128

> **PKCS12_SHA1_RC4_128**: `object`

PKCS#12 PBE with SHA-1 and 128-bit RC4.

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

---

### PKCS12_SHA1_RC4_40

> **PKCS12_SHA1_RC4_40**: `object`

PKCS#12 PBE with SHA-1 and 40-bit RC4.

#### iterationCount

> **iterationCount**: `number`

Number of iterations

#### salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation
