[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/types](../README.md) / SymmetricEncryptionAlgorithmParamsMap

# Interface: SymmetricEncryptionAlgorithmParamsMap

Parameter mapping for symmetric encryption algorithms.
Includes both standalone symmetric algorithms and password-based encryption.

## Extends

- [`PbeAlgorithmParamsMap`](PbeAlgorithmParamsMap.md)

## Properties

### AES_128_CBC

> **AES_128_CBC**: `object`

#### disablePadding?

> `optional` **disablePadding**: `boolean`

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

---

### AES_128_CCM

> **AES_128_CCM**: `object`

AES-128 in Counter with CBC-MAC Mode parameters.

#### icvLen?

> `optional` **icvLen**: `number`

Authentication tag length in bytes

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

Initialization vector/nonce

---

### AES_128_ECB

> **AES_128_ECB**: `object`

#### disablePadding?

> `optional` **disablePadding**: `boolean`

---

### AES_128_GCM

> **AES_128_GCM**: `object`

AES-128 in Galois/Counter Mode parameters.

#### icvLen?

> `optional` **icvLen**: `number`

Authentication tag length in bytes

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

Initialization vector/nonce

---

### AES_192_CBC

> **AES_192_CBC**: `object`

#### disablePadding?

> `optional` **disablePadding**: `boolean`

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

---

### AES_192_CCM

> **AES_192_CCM**: `object`

#### icvLen?

> `optional` **icvLen**: `number`

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

---

### AES_192_ECB

> **AES_192_ECB**: `object`

#### disablePadding?

> `optional` **disablePadding**: `boolean`

---

### AES_192_GCM

> **AES_192_GCM**: `object`

AES-192 in Galois/Counter Mode parameters.

#### icvLen?

> `optional` **icvLen**: `number`

Authentication tag length in bytes

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

Initialization vector/nonce

---

### AES_256_CBC

> **AES_256_CBC**: `object`

#### disablePadding?

> `optional` **disablePadding**: `boolean`

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

---

### AES_256_CCM

> **AES_256_CCM**: `object`

#### icvLen?

> `optional` **icvLen**: `number`

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

---

### AES_256_ECB

> **AES_256_ECB**: `object`

#### disablePadding?

> `optional` **disablePadding**: `boolean`

---

### AES_256_GCM

> **AES_256_GCM**: `object`

AES-256 in Galois/Counter Mode parameters.

#### icvLen?

> `optional` **icvLen**: `number`

Authentication tag length in bytes

#### nonce

> **nonce**: `Uint8Array`\<`ArrayBuffer`\>

Initialization vector/nonce

---

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

#### Inherited from

[`PbeAlgorithmParamsMap`](PbeAlgorithmParamsMap.md).[`PBES2`](PbeAlgorithmParamsMap.md#pbes2)
