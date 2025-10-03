[**PKI-Lite**](../../README.md)

---

[PKI-Lite](../../README.md) / [pki-lite-crypto-extended](../README.md) / WebCryptoExtendedProvider

# Class: WebCryptoExtendedProvider

Extended WebCryptoProvider that adds support for additional algorithms
such as MD5 hashing, AES ECB mode, and certain PBE algorithms.

Note: This implementation uses the 'node-forge' library for RSA encryption/decryption
with PKCS#1 v1.5 padding, as WebCrypto does not support this mode directly.

Caution: MD5 is considered cryptographically weak and should be used with caution.
This provider is intended for compatibility with legacy systems and not for secure applications.

## Example

```ts
const provider = new WebCryptoExtendedProvider()
const hash = await provider.digest(data, 'MD5')
const encrypted = await provider.encryptSymmetric(data, key, {
    type: 'AES_128_ECB',
})
const decrypted = await provider.decryptSymmetric(encryptedData, key, {
    type: 'AES_128_ECB',
})
const rsaEncrypted = await provider.encrypt(data, publicKeyInfo, {
    type: 'RSASSA_PKCS1_v1_5',
})
const rsaDecrypted = await provider.decrypt(rsaEncryptedData, privateKeyInfo, {
    type: 'RSASSA_PKCS1_v1_5',
})
```

## Extends

- [`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md)

## Constructors

### Constructor

> **new WebCryptoExtendedProvider**(): `WebCryptoExtendedProvider`

#### Returns

`WebCryptoExtendedProvider`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`constructor`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#constructor)

## Methods

### contentEncryptionAlgorithm()

> **contentEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts symmetric encryption algorithm parameters to a content encryption algorithm identifier.

#### Parameters

##### encryptionParams

The symmetric encryption algorithm parameters

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md) | \{ \}

#### Returns

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Content encryption algorithm as an AlgorithmIdentifier

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`contentEncryptionAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#contentencryptionalgorithm)

---

### decrypt()

> **decrypt**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Decrypts the given data using the specified private key and asymmetric algorithm.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to decrypt

##### privateKeyInfo

[`PrivateKeyInfo`](../../pki-lite/keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The private key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The decryption algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`decrypt`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#decrypt)

---

### decryptSymmetric()

> **decryptSymmetric**(`data`, `key`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Decrypts the given data using the specified symmetric key and algorithm.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to decrypt

##### key

`Uint8Array`\<`ArrayBuffer`\>

The symmetric key to use for decryption

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The decryption algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`decryptSymmetric`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#decryptsymmetric)

---

### digest()

> **digest**(`data`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Computes a cryptographic hash of the input data.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to hash

##### algorithm

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

The hash algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

The computed hash bytes

#### Throws

UnsupportedCryptoAlgorithm if the algorithm is not supported

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`digest`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#digest)

---

### encrypt()

> **encrypt**(`data`, `publicKeyInfo`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Encrypts data using asymmetric (public key) cryptography.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to encrypt

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../pki-lite/keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The public key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`encrypt`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#encrypt)

---

### encryptSymmetric()

> **encryptSymmetric**(`data`, `key`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Encrypts the given data using the specified symmetric key and algorithm.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to encrypt

##### key

`Uint8Array`\<`ArrayBuffer`\>

The symmetric key to use for encryption

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`encryptSymmetric`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#encryptsymmetric)

---

### toSymmetricEncryptionAlgorithmParams()

> **toSymmetricEncryptionAlgorithmParams**(`algorithm`): [`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Converts an ASN.1 algorithm identifier to symmetric encryption algorithm parameters.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

#### Returns

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm parameters

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`toSymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#tosymmetricencryptionalgorithmparams)
