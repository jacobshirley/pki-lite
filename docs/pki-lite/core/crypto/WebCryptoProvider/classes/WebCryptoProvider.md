[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/WebCryptoProvider](../README.md) / WebCryptoProvider

# Class: WebCryptoProvider

Cryptographic provider implementation using the Web Crypto API.

This provider leverages the browser's native Web Crypto API for cryptographic
operations, offering excellent performance and security. It supports modern
algorithms including RSA, ECDSA, AES, and SHA hashes. The Web Crypto API is
available in both browsers and Node.js (16+), making this provider suitable
for cross-platform applications.

Supported operations:

- Hashing: SHA-1, SHA-256, SHA-384, SHA-512 (MD5 not supported)
- Asymmetric: RSA-PKCS1, RSA-PSS, RSA-OAEP, ECDSA, ECDH
- Symmetric: AES-GCM, AES-CBC, AES-CTR
- Key derivation: PBKDF2, HKDF

## Example

```typescript
const provider = new WebCryptoProvider()

// Hash data
const hash = await provider.digest(data, 'SHA-256')

// Sign data with RSA-PSS
const signature = await provider.sign(data, privateKeyInfo, {
    type: 'RSA_PSS',
    params: { hash: 'SHA-256', saltLength: 32 },
})

// Encrypt with AES-GCM
const encrypted = await provider.encryptSymmetric(plaintext, key, {
    type: 'AES_GCM',
    params: { iv: iv, tagLength: 16 },
})
```

## Extended by

- [`WebCryptoExtendedProvider`](../../../../../pki-lite-crypto-extended/classes/WebCryptoExtendedProvider.md)

## Implements

- [`CryptoProvider`](../../types/interfaces/CryptoProvider.md)

## Constructors

### Constructor

> **new WebCryptoProvider**(): `WebCryptoProvider`

#### Returns

`WebCryptoProvider`

## Properties

### crypto

> `protected` **crypto**: `object` = `globalThis.crypto`

Reference to the Web Crypto API interface.
Protected to allow testing with mock implementations.

#### subtle

> **subtle**: `SubtleCrypto`

## Methods

### contentEncryptionAlgorithm()

> **contentEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts symmetric encryption algorithm parameters to a content encryption algorithm identifier.

#### Parameters

##### encryptionParams

The symmetric encryption algorithm parameters

[`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md) | [`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

#### Returns

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Content encryption algorithm as an AlgorithmIdentifier

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`contentEncryptionAlgorithm`](../../types/interfaces/CryptoProvider.md#contentencryptionalgorithm)

---

### decrypt()

> **decrypt**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Decrypts the given data using the specified private key and asymmetric algorithm.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to decrypt

##### privateKeyInfo

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The private key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The decryption algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`decrypt`](../../types/interfaces/CryptoProvider.md#decrypt)

---

### decryptSymmetric()

> **decryptSymmetric**(`data`, `key`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Decrypts the given data using the specified symmetric key and algorithm.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to decrypt

##### key

The symmetric key to use for decryption

`string` | `Uint8Array`\<`ArrayBuffer`\> | `CryptoKey`

##### algorithm

The decryption algorithm to use

[`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md) | [`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`decryptSymmetric`](../../types/interfaces/CryptoProvider.md#decryptsymmetric)

---

### deriveCryptoKey()

> `protected` **deriveCryptoKey**(`password`, `algorithm`): `Promise`\<`CryptoKey`\>

#### Parameters

##### password

`string` | `Uint8Array`\<`ArrayBuffer`\> | `CryptoKey`

##### algorithm

[`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

#### Returns

`Promise`\<`CryptoKey`\>

---

### deriveKey()

> **deriveKey**(`password`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Derives a cryptographic key from a password using the specified algorithm.

#### Parameters

##### password

The password or key material to derive from

`string` | `Uint8Array`\<`ArrayBuffer`\> | `CryptoKey`

##### algorithm

[`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

The key derivation algorithm parameters

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the derived key as a Uint8Array<ArrayBuffer>

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`deriveKey`](../../types/interfaces/CryptoProvider.md#derivekey)

---

### derivePkcs12Key()

> **derivePkcs12Key**(`password`, `salt`, `iterationCount`, `keyLength`, `purpose`, `hash`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Derives key material using PKCS#12 password-based KDF (RFC 7292 Appendix B).
Supports modern hash algorithms for improved security while maintaining OpenSSL compatibility.

#### Parameters

##### password

The password (string or bytes, will be converted to BMPString format)

`string` | `Uint8Array`\<`ArrayBuffer`\>

##### salt

`Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

##### iterationCount

`number`

Number of iterations for key strengthening

##### keyLength

`number`

Desired key length in bytes

##### purpose

Key purpose: 'encryption' (id=1), 'iv' (id=2), or 'mac' (id=3)

`"encryption"` | `"iv"` | `"mac"`

##### hash

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md) = `'SHA-1'`

Hash algorithm to use (default: SHA-1 for legacy compatibility)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the derived key bytes

#### Example

```typescript
// Derive a MAC key with SHA-256
const macKey = await provider.derivePkcs12Key(
    password,
    salt,
    100000,
    32,
    'mac',
    'SHA-256',
)
```

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`derivePkcs12Key`](../../types/interfaces/CryptoProvider.md#derivepkcs12key)

---

### digest()

> **digest**(`data`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Computes a cryptographic hash of the input data.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to hash

##### algorithm

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

The hash algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

The computed hash bytes

#### Throws

UnsupportedCryptoAlgorithmError if the algorithm is not supported

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`digest`](../../types/interfaces/CryptoProvider.md#digest)

---

### digestAlgorithm()

> **digestAlgorithm**(`hash`): [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts a hash algorithm to a digest algorithm identifier.

#### Parameters

##### hash

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

The hash algorithm

#### Returns

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Digest algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`digestAlgorithm`](../../types/interfaces/CryptoProvider.md#digestalgorithm)

---

### encrypt()

> **encrypt**(`data`, `publicKeyInfo`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Encrypts data using asymmetric (public key) cryptography.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to encrypt

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The public key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`encrypt`](../../types/interfaces/CryptoProvider.md#encrypt)

---

### encryptSymmetric()

> **encryptSymmetric**(`data`, `key`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Encrypts the given data using the specified symmetric key and algorithm.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to encrypt

##### key

The symmetric key to use for encryption

`string` | `Uint8Array`\<`ArrayBuffer`\> | `CryptoKey`

##### algorithm

The encryption algorithm to use

[`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md) | [`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`encryptSymmetric`](../../types/interfaces/CryptoProvider.md#encryptsymmetric)

---

### generateKeyPair()

> **generateKeyPair**(`options`): `Promise`\<\{ `privateKey`: `Uint8Array`\<`ArrayBuffer`\>; `publicKey`: `Uint8Array`\<`ArrayBuffer`\>; \}\>

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

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

`Promise`\<\{ `privateKey`: `Uint8Array`\<`ArrayBuffer`\>; `publicKey`: `Uint8Array`\<`ArrayBuffer`\>; \}\>

A Promise that resolves to an object containing the public and private keys

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`generateKeyPair`](../../types/interfaces/CryptoProvider.md#generatekeypair)

---

### generateSymmetricKey()

> **generateSymmetricKey**(`algorithm`): `Uint8Array`\<`ArrayBuffer`\>

Generates a symmetric key for the specified encryption algorithm.

#### Parameters

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The generated symmetric key as a Uint8Array<ArrayBuffer>

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`generateSymmetricKey`](../../types/interfaces/CryptoProvider.md#generatesymmetrickey)

---

### getEcCurveParameters()

> **getEcCurveParameters**(`encryptionParams`): [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Gets the EC curve parameters for a given asymmetric encryption algorithm.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

EC curve parameters as a Uint8Array<ArrayBuffer> or ObjectIdentifier

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`getEcCurveParameters`](../../types/interfaces/CryptoProvider.md#geteccurveparameters)

---

### getEcNamedCurve()

> **getEcNamedCurve**(`algorithm`, `publicKeyInfo?`): [`NamedCurve`](../../types/type-aliases/NamedCurve.md)

Extracts the EC named curve from an algorithm identifier or public key.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

Optional public key information to extract curve from

#### Returns

[`NamedCurve`](../../types/type-aliases/NamedCurve.md)

The EC named curve identifier

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`getEcNamedCurve`](../../types/interfaces/CryptoProvider.md#getecnamedcurve)

---

### getKeyMaterial()

> `protected` **getKeyMaterial**(`password`): `Promise`\<`CryptoKey`\>

#### Parameters

##### password

`string` | `Uint8Array`\<`ArrayBuffer`\>

#### Returns

`Promise`\<`CryptoKey`\>

---

### getRandomValues()

> **getRandomValues**(`length`): `Uint8Array`\<`ArrayBuffer`\>

Generates cryptographically secure random bytes.

#### Parameters

##### length

`number`

The number of random bytes to generate

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

Array containing the random bytes

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`getRandomValues`](../../types/interfaces/CryptoProvider.md#getrandomvalues)

---

### getWebCryptoAlgorithm()

> **getWebCryptoAlgorithm**(`algorithm`): `EcKeyImportParams` \| `RsaPssParams` \| `RsaOaepParams` \| `RsaHashedKeyAlgorithm`

**`Internal`**

Converts PKI algorithm parameters to Web Crypto API algorithm specification.

#### Parameters

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The PKI algorithm parameters

#### Returns

`EcKeyImportParams` \| `RsaPssParams` \| `RsaOaepParams` \| `RsaHashedKeyAlgorithm`

Web Crypto API compatible algorithm specification

---

### getWebCryptoDerivationAlgorithm()

> **getWebCryptoDerivationAlgorithm**(`algorithm`): `Pbkdf2Params`

#### Parameters

##### algorithm

###### params

\{ `hash`: [`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array`\<`ArrayBuffer`\>; \}

###### params.hash

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.iterationCount

`number`

Number of iterations

###### params.keyLength?

`number`

Desired key length in bytes (optional)

###### params.salt

`Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

###### type

`"PBKDF2"`

#### Returns

`Pbkdf2Params`

---

### getWebCryptoSymmetricAlgorithm()

> **getWebCryptoSymmetricAlgorithm**(`algorithm`): `AesCbcParams` \| `AesGcmParams`

#### Parameters

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

#### Returns

`AesCbcParams` \| `AesGcmParams`

---

### getWebCryptoSymmetricKeyGenAlgorithm()

> **getWebCryptoSymmetricKeyGenAlgorithm**(`algorithm`): `AesDerivedKeyParams`

#### Parameters

##### algorithm

`"PBES2"` | `"AES_128_GCM"` | `"AES_192_GCM"` | `"AES_256_GCM"` | `"AES_128_CCM"` | `"AES_192_CCM"` | `"AES_256_CCM"` | `"AES_128_CBC"` | `"AES_192_CBC"` | `"AES_256_CBC"` | `"AES_128_ECB"` | `"AES_192_ECB"` | `"AES_256_ECB"` | `"PKCS12_SHA1_RC4_128"` | `"PKCS12_SHA1_RC4_40"` | `"PKCS12_SHA1_3DES_3KEY"` | `"PKCS12_SHA1_3DES_2KEY"` | `"PKCS12_SHA1_RC2_128"` | `"PKCS12_SHA1_RC2_40"`

#### Returns

`AesDerivedKeyParams`

---

### hmac()

> **hmac**(`key`, `data`, `hash`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Computes an HMAC (Hash-based Message Authentication Code) of the input data.

#### Parameters

##### key

`Uint8Array`\<`ArrayBuffer`\>

The secret key for HMAC

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to authenticate

##### hash

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

The hash algorithm to use

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

The computed HMAC bytes

#### Throws

UnsupportedCryptoAlgorithmError if the algorithm is not supported

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`hmac`](../../types/interfaces/CryptoProvider.md#hmac)

---

### keyEncryptionAlgorithm()

> **keyEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts asymmetric encryption algorithm parameters to a key encryption algorithm identifier.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Key encryption algorithm as an AlgorithmIdentifier

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`keyEncryptionAlgorithm`](../../types/interfaces/CryptoProvider.md#keyencryptionalgorithm)

---

### sign()

> **sign**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Creates a digital signature for the given data.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data to sign

##### privateKeyInfo

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The signer's private key

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The signature algorithm and parameters

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

Promise resolving to the signature bytes

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`sign`](../../types/interfaces/CryptoProvider.md#sign)

---

### signatureAlgorithm()

> **signatureAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts asymmetric encryption algorithm parameters to a signature algorithm identifier.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Signature algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`signatureAlgorithm`](../../types/interfaces/CryptoProvider.md#signaturealgorithm)

---

### toAsymmetricEncryptionAlgorithmParams()

> **toAsymmetricEncryptionAlgorithmParams**(`algorithm`, `publicKeyInfo?`): [`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Converts an ASN.1 algorithm identifier to asymmetric encryption algorithm parameters.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

Optional public key information for context

#### Returns

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Asymmetric encryption algorithm parameters

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`toAsymmetricEncryptionAlgorithmParams`](../../types/interfaces/CryptoProvider.md#toasymmetricencryptionalgorithmparams)

---

### toDerivationAlgorithmParams()

> **toDerivationAlgorithmParams**(`algorithm`): `object`

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

#### Returns

`object`

##### params

> **params**: `object`

###### params.hash

> **hash**: [`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

Hash algorithm for HMAC

###### params.iterationCount

> **iterationCount**: `number`

Number of iterations

###### params.keyLength?

> `optional` **keyLength**: `number`

Desired key length in bytes (optional)

###### params.salt

> **salt**: `Uint8Array`\<`ArrayBuffer`\>

Salt value for key derivation

##### type

> **type**: `"PBKDF2"`

---

### toHashAlgorithm()

> **toHashAlgorithm**(`algorithm`): [`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

Converts an ASN.1 algorithm identifier to a hash algorithm.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

#### Returns

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

The hash algorithm

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`toHashAlgorithm`](../../types/interfaces/CryptoProvider.md#tohashalgorithm)

---

### toPbeAlgorithmParams()

> **toPbeAlgorithmParams**(`algorithm`): [`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

#### Returns

[`PbeAlgorithmParams`](../../types/type-aliases/PbeAlgorithmParams.md)

---

### toSymmetricEncryptionAlgorithmParams()

> **toSymmetricEncryptionAlgorithmParams**(`algorithm`): [`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Converts an ASN.1 algorithm identifier to symmetric encryption algorithm parameters.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

#### Returns

[`SymmetricEncryptionAlgorithmParams`](../../types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm parameters

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`toSymmetricEncryptionAlgorithmParams`](../../types/interfaces/CryptoProvider.md#tosymmetricencryptionalgorithmparams)

---

### verify()

> **verify**(`data`, `publicKeyInfo`, `signature`, `algorithm`): `Promise`\<`boolean`\>

Verifies a digital signature against the original data.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The original data that was signed

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The signer's public key

##### signature

`Uint8Array`\<`ArrayBuffer`\>

The signature to verify

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../../types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The signature algorithm and parameters

#### Returns

`Promise`\<`boolean`\>

Promise resolving to true if signature is valid

#### Implementation of

[`CryptoProvider`](../../types/interfaces/CryptoProvider.md).[`verify`](../../types/interfaces/CryptoProvider.md#verify)
