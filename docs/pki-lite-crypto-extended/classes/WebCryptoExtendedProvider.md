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

## Properties

### crypto

> `protected` **crypto**: `object`

Reference to the Web Crypto API interface.
Protected to allow testing with mock implementations.

#### subtle

> **subtle**: `SubtleCrypto`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`crypto`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#crypto)

## Methods

### contentEncryptionAlgorithm()

> **contentEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts symmetric encryption algorithm parameters to a content encryption algorithm identifier.

#### Parameters

##### encryptionParams

The symmetric encryption algorithm parameters

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md) | \{ `params`: \{ `derivationAlgorithm`: \{ `params`: \{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}; `encryptionAlgorithm`: [`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md); \}; `type`: `"PBES2"`; \}

#### Returns

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Content encryption algorithm as an AlgorithmIdentifier

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`contentEncryptionAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#contentencryptionalgorithm)

---

### decrypt()

> **decrypt**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Decrypts the given data using the specified private key and asymmetric algorithm.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to decrypt

##### privateKeyInfo

[`PrivateKeyInfo`](../../pki-lite/keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The private key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The decryption algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`decrypt`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#decrypt)

---

### decryptSymmetric()

> **decryptSymmetric**(`data`, `key`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Decrypts the given data using the specified symmetric key and algorithm.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to decrypt

##### key

`Uint8Array<ArrayBuffer>`

The symmetric key to use for decryption

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The decryption algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`decryptSymmetric`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#decryptsymmetric)

---

### deriveCryptoKey()

> `protected` **deriveCryptoKey**(`password`, `algorithm`): `Promise`\<`CryptoKey`\>

#### Parameters

##### password

`string` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> | `CryptoKey`

##### algorithm

###### params

\{ `derivationAlgorithm`: \{ `params`: \{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}; `encryptionAlgorithm`: [`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md); \}

###### params.derivationAlgorithm

\{ `params`: \{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}

Key derivation algorithm and parameters

###### params.derivationAlgorithm.params

\{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}

###### params.derivationAlgorithm.params.hash

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.derivationAlgorithm.params.iterationCount

`number`

Number of iterations

###### params.derivationAlgorithm.params.keyLength?

`number`

Desired key length in bytes (optional)

###### params.derivationAlgorithm.params.salt

`Uint8Array<ArrayBuffer>`

Salt value for key derivation

###### params.derivationAlgorithm.type

`"PBKDF2"`

###### params.encryptionAlgorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm and parameters

###### type

`"PBES2"`

#### Returns

`Promise`\<`CryptoKey`\>

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`deriveCryptoKey`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#derivecryptokey)

---

### deriveKey()

> **deriveKey**(`password`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Derives a cryptographic key from a password using the specified algorithm.

#### Parameters

##### password

The password or key material to derive from

`string` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> | `CryptoKey`

##### algorithm

The key derivation algorithm parameters

###### params

\{ `derivationAlgorithm`: \{ `params`: \{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}; `encryptionAlgorithm`: [`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md); \}

###### params.derivationAlgorithm

\{ `params`: \{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}

Key derivation algorithm and parameters

###### params.derivationAlgorithm.params

\{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}

###### params.derivationAlgorithm.params.hash

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.derivationAlgorithm.params.iterationCount

`number`

Number of iterations

###### params.derivationAlgorithm.params.keyLength?

`number`

Desired key length in bytes (optional)

###### params.derivationAlgorithm.params.salt

`Uint8Array<ArrayBuffer>`

Salt value for key derivation

###### params.derivationAlgorithm.type

`"PBKDF2"`

###### params.encryptionAlgorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm and parameters

###### type

`"PBES2"`

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the derived key as a Uint8Array<ArrayBuffer>

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`deriveKey`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#derivekey)

---

### digest()

> **digest**(`data`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Computes a cryptographic hash of the input data.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to hash

##### algorithm

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

The hash algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

The computed hash bytes

#### Throws

UnsupportedCryptoAlgorithm if the algorithm is not supported

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`digest`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#digest)

---

### digestAlgorithm()

> **digestAlgorithm**(`hash`): [`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts a hash algorithm to a digest algorithm identifier.

#### Parameters

##### hash

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

The hash algorithm

#### Returns

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Digest algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`digestAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#digestalgorithm)

---

### encrypt()

> **encrypt**(`data`, `publicKeyInfo`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Encrypts data using asymmetric (public key) cryptography.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to encrypt

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../pki-lite/keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The public key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`encrypt`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#encrypt)

---

### encryptSymmetric()

> **encryptSymmetric**(`data`, `key`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Encrypts the given data using the specified symmetric key and algorithm.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to encrypt

##### key

`Uint8Array<ArrayBuffer>`

The symmetric key to use for encryption

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

#### Overrides

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`encryptSymmetric`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#encryptsymmetric)

---

### generateKeyPair()

> **generateKeyPair**(`options`): `Promise`\<\{ `privateKey`: `Uint8Array<ArrayBuffer>`; `publicKey`: `Uint8Array<ArrayBuffer>`; \}\>

Generates an asymmetric key pair for the specified algorithm and options.

#### Parameters

##### options

Configuration options including algorithm, key size, and other parameters

###### algorithm

`"RSA"` \| `"EC"`

###### hash?

`string`

###### keySize?

`number`

###### namedCurve?

`string`

###### publicExponent?

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<\{ `privateKey`: `Uint8Array<ArrayBuffer>`; `publicKey`: `Uint8Array<ArrayBuffer>`; \}\>

A Promise that resolves to an object containing the public and private keys

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`generateKeyPair`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#generatekeypair)

---

### generateSymmetricKey()

> **generateSymmetricKey**(`algorithm`): `Uint8Array<ArrayBuffer>`

Generates a symmetric key for the specified encryption algorithm.

#### Parameters

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Uint8Array<ArrayBuffer>`

The generated symmetric key as a Uint8Array<ArrayBuffer>

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`generateSymmetricKey`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#generatesymmetrickey)

---

### getEcCurveParameters()

> **getEcCurveParameters**(`encryptionParams`): [`ObjectIdentifier`](../../pki-lite/asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Gets the EC curve parameters for a given asymmetric encryption algorithm.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`ObjectIdentifier`](../../pki-lite/asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

EC curve parameters as a Uint8Array<ArrayBuffer> or ObjectIdentifier

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getEcCurveParameters`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#geteccurveparameters)

---

### getEcNamedCurve()

> **getEcNamedCurve**(`algorithm`, `publicKeyInfo?`): [`NamedCurve`](../../pki-lite/core/crypto/types/type-aliases/NamedCurve.md)

Extracts the EC named curve from an algorithm identifier or public key.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../pki-lite/keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

Optional public key information to extract curve from

#### Returns

[`NamedCurve`](../../pki-lite/core/crypto/types/type-aliases/NamedCurve.md)

The EC named curve identifier

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getEcNamedCurve`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getecnamedcurve)

---

### getKeyMaterial()

> `protected` **getKeyMaterial**(`password`): `Promise`\<`CryptoKey`\>

#### Parameters

##### password

`string` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<`CryptoKey`\>

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getKeyMaterial`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getkeymaterial)

---

### getRandomValues()

> **getRandomValues**(`length`): `Uint8Array<ArrayBuffer>`

Generates cryptographically secure random bytes.

#### Parameters

##### length

`number`

The number of random bytes to generate

#### Returns

`Uint8Array<ArrayBuffer>`

Array containing the random bytes

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getRandomValues`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getrandomvalues)

---

### getWebCryptoAlgorithm()

> **getWebCryptoAlgorithm**(`algorithm`): `RsaPssParams` \| `EcKeyImportParams` \| `RsaOaepParams` \| `RsaHashedKeyAlgorithm`

**`Internal`**

Converts PKI algorithm parameters to Web Crypto API algorithm specification.

#### Parameters

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The PKI algorithm parameters

#### Returns

`RsaPssParams` \| `EcKeyImportParams` \| `RsaOaepParams` \| `RsaHashedKeyAlgorithm`

Web Crypto API compatible algorithm specification

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getWebCryptoAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getwebcryptoalgorithm)

---

### getWebCryptoDerivationAlgorithm()

> **getWebCryptoDerivationAlgorithm**(`algorithm`): `Pbkdf2Params`

#### Parameters

##### algorithm

###### params

\{ `hash`: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}

###### params.hash

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.iterationCount

`number`

Number of iterations

###### params.keyLength?

`number`

Desired key length in bytes (optional)

###### params.salt

`Uint8Array<ArrayBuffer>`

Salt value for key derivation

###### type

`"PBKDF2"`

#### Returns

`Pbkdf2Params`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getWebCryptoDerivationAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getwebcryptoderivationalgorithm)

---

### getWebCryptoSymmetricAlgorithm()

> **getWebCryptoSymmetricAlgorithm**(`algorithm`): `AesCbcParams` \| `AesGcmParams`

#### Parameters

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

#### Returns

`AesCbcParams` \| `AesGcmParams`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getWebCryptoSymmetricAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getwebcryptosymmetricalgorithm)

---

### getWebCryptoSymmetricKeyGenAlgorithm()

> **getWebCryptoSymmetricKeyGenAlgorithm**(`algorithm`): `AesDerivedKeyParams`

#### Parameters

##### algorithm

`"SHA1_3DES_2KEY_CBC"` | `"SHA1_3DES_3KEY_CBC"` | `"SHA1_RC2_40_CBC"` | `"SHA1_RC2_128_CBC"` | `"AES_128_GCM"` | `"AES_192_GCM"` | `"AES_256_GCM"` | `"AES_128_CCM"` | `"AES_192_CCM"` | `"AES_256_CCM"` | `"AES_128_CBC"` | `"AES_192_CBC"` | `"AES_256_CBC"` | `"AES_128_ECB"` | `"AES_192_ECB"` | `"AES_256_ECB"` | `"PBES2"`

#### Returns

`AesDerivedKeyParams`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`getWebCryptoSymmetricKeyGenAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#getwebcryptosymmetrickeygenalgorithm)

---

### keyEncryptionAlgorithm()

> **keyEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts asymmetric encryption algorithm parameters to a key encryption algorithm identifier.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Key encryption algorithm as an AlgorithmIdentifier

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`keyEncryptionAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#keyencryptionalgorithm)

---

### sign()

> **sign**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Creates a digital signature for the given data.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to sign

##### privateKeyInfo

[`PrivateKeyInfo`](../../pki-lite/keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The signer's private key

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The signature algorithm and parameters

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the signature bytes

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`sign`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#sign)

---

### signatureAlgorithm()

> **signatureAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts asymmetric encryption algorithm parameters to a signature algorithm identifier.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Signature algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`signatureAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#signaturealgorithm)

---

### toAsymmetricEncryptionAlgorithmParams()

> **toAsymmetricEncryptionAlgorithmParams**(`algorithm`, `publicKeyInfo?`): [`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Converts an ASN.1 algorithm identifier to asymmetric encryption algorithm parameters.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../pki-lite/keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

Optional public key information for context

#### Returns

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Asymmetric encryption algorithm parameters

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`toAsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#toasymmetricencryptionalgorithmparams)

---

### toDerivationAlgorithmParams()

> **toDerivationAlgorithmParams**(`algorithm`): `object`

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

#### Returns

`object`

##### params

> **params**: `object`

###### params.hash

> **hash**: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.iterationCount

> **iterationCount**: `number`

Number of iterations

###### params.keyLength?

> `optional` **keyLength**: `number`

Desired key length in bytes (optional)

###### params.salt

> **salt**: `Uint8Array<ArrayBuffer>`

Salt value for key derivation

##### type

> **type**: `"PBKDF2"`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`toDerivationAlgorithmParams`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#toderivationalgorithmparams)

---

### toHashAlgorithm()

> **toHashAlgorithm**(`algorithm`): [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

Converts an ASN.1 algorithm identifier to a hash algorithm.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

#### Returns

[`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

The hash algorithm

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`toHashAlgorithm`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#tohashalgorithm)

---

### toPbeAlgorithmParams()

> **toPbeAlgorithmParams**(`algorithm`): `object`

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../pki-lite/algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

#### Returns

`object`

##### params

> **params**: `object`

###### params.derivationAlgorithm

> **derivationAlgorithm**: `object`

Key derivation algorithm and parameters

###### params.derivationAlgorithm.params

> **params**: `object`

###### params.derivationAlgorithm.params.hash

> **hash**: [`HashAlgorithm`](../../pki-lite/core/crypto/types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.derivationAlgorithm.params.iterationCount

> **iterationCount**: `number`

Number of iterations

###### params.derivationAlgorithm.params.keyLength?

> `optional` **keyLength**: `number`

Desired key length in bytes (optional)

###### params.derivationAlgorithm.params.salt

> **salt**: `Uint8Array<ArrayBuffer>`

Salt value for key derivation

###### params.derivationAlgorithm.type

> **type**: `"PBKDF2"`

###### params.encryptionAlgorithm

> **encryptionAlgorithm**: [`SymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm and parameters

##### type

> **type**: `"PBES2"`

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`toPbeAlgorithmParams`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#topbealgorithmparams)

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

---

### verify()

> **verify**(`data`, `publicKeyInfo`, `signature`, `algorithm`): `Promise`\<`boolean`\>

Verifies a digital signature against the original data.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The original data that was signed

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../pki-lite/keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The signer's public key

##### signature

`Uint8Array<ArrayBuffer>`

The signature to verify

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../pki-lite/core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The signature algorithm and parameters

#### Returns

`Promise`\<`boolean`\>

Promise resolving to true if signature is valid

#### Inherited from

[`WebCryptoProvider`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md).[`verify`](../../pki-lite/core/crypto/WebCryptoProvider/classes/WebCryptoProvider.md#verify)
