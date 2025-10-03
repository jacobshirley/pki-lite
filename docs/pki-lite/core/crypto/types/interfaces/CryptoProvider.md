[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/types](../README.md) / CryptoProvider

# Interface: CryptoProvider

Interface defining the cryptographic operations required by the PKI library.

This interface abstracts cryptographic operations to allow different implementations
based on available platforms and algorithm requirements. The default WebCryptoProvider
uses the Web Crypto API, while extended providers can support additional algorithms
and legacy cryptographic functions.

Implementations must provide:

- Hashing operations for message digests
- Digital signature creation and verification
- Asymmetric encryption and decryption
- Symmetric encryption and decryption
- Key derivation functions
- Random number generation

## Example

```typescript
class CustomCryptoProvider implements CryptoProvider {
    async digest(
        data: Uint8Array<ArrayBuffer>,
        algorithm: HashAlgorithm,
    ): Promise<Uint8Array<ArrayBuffer>> {
        // Custom hash implementation
        return customHash(data, algorithm)
    }

    // Implement other required methods...
}

// Use custom provider
setCryptoProvider(new CustomCryptoProvider())
```

## Methods

### contentEncryptionAlgorithm()

> **contentEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts symmetric encryption algorithm parameters to a content encryption algorithm identifier.

#### Parameters

##### encryptionParams

[`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md)

The symmetric encryption algorithm parameters

#### Returns

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Content encryption algorithm as an AlgorithmIdentifier

---

### decrypt()

> **decrypt**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Decrypts the given data using the specified private key and asymmetric algorithm.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to decrypt

##### privateKeyInfo

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The private key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The decryption algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

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

The decryption algorithm to use

[`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md) | \{ `params`: \{ `derivationAlgorithm`: \{ `params`: \{ `hash`: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}; `encryptionAlgorithm`: [`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md); \}; `type`: `"PBES2"`; \}

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the decrypted data as a Uint8Array<ArrayBuffer>

---

### deriveKey()

> **deriveKey**(`password`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Derives a cryptographic key from a password using the specified algorithm.

#### Parameters

##### password

The password or key material to derive from

`string` | `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

##### algorithm

The key derivation algorithm parameters

###### params

\{ `derivationAlgorithm`: \{ `params`: \{ `hash`: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}; `encryptionAlgorithm`: [`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md); \}

###### params.derivationAlgorithm

\{ `params`: \{ `hash`: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}

Key derivation algorithm and parameters

###### params.derivationAlgorithm.params

\{ `hash`: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}

###### params.derivationAlgorithm.params.hash

[`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

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

[`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm and parameters

###### type

`"PBES2"`

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the derived key as a Uint8Array<ArrayBuffer>

---

### digest()

> **digest**(`data`, `hash`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Computes the cryptographic hash digest of the given data.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to hash

##### hash

[`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the hash digest bytes

---

### digestAlgorithm()

> **digestAlgorithm**(`algorithm`): `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts a hash algorithm to a digest algorithm identifier.

#### Parameters

##### algorithm

[`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

The hash algorithm

#### Returns

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Digest algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier

---

### encrypt()

> **encrypt**(`data`, `publicKeyInfo`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Encrypts data using asymmetric (public key) cryptography.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to encrypt

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The public key information

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

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

The encryption algorithm to use

[`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md) | \{ `params`: \{ `derivationAlgorithm`: \{ `params`: \{ `hash`: [`HashAlgorithm`](../type-aliases/HashAlgorithm.md); `iterationCount`: `number`; `keyLength?`: `number`; `salt`: `Uint8Array<ArrayBuffer>`; \}; `type`: `"PBKDF2"`; \}; `encryptionAlgorithm`: [`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md); \}; `type`: `"PBES2"`; \}

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the encrypted data as a Uint8Array<ArrayBuffer>

---

### generateKeyPair()

> **generateKeyPair**(`options`): `Promise`\<[`KeyPair`](../type-aliases/KeyPair.md)\>

Generates an asymmetric key pair for the specified algorithm and options.

#### Parameters

##### options

[`KeyPairGenOptions`](../type-aliases/KeyPairGenOptions.md)

Configuration options including algorithm, key size, and other parameters

#### Returns

`Promise`\<[`KeyPair`](../type-aliases/KeyPair.md)\>

A Promise that resolves to an object containing the public and private keys

---

### generateSymmetricKey()

> **generateSymmetricKey**(`algorithm`): `Uint8Array<ArrayBuffer>`

Generates a symmetric key for the specified encryption algorithm.

#### Parameters

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md)

The encryption algorithm to use

#### Returns

`Uint8Array<ArrayBuffer>`

The generated symmetric key as a Uint8Array<ArrayBuffer>

---

### getEcCurveParameters()

> **getEcCurveParameters**(`algorithm`): `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Gets the EC curve parameters for a given asymmetric encryption algorithm.

#### Parameters

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

EC curve parameters as a Uint8Array<ArrayBuffer> or ObjectIdentifier

---

### getEcNamedCurve()

> **getEcNamedCurve**(`algorithm`, `publicKeyInfo?`): [`NamedCurve`](../type-aliases/NamedCurve.md)

Extracts the EC named curve from an algorithm identifier or public key.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

Optional public key information to extract curve from

#### Returns

[`NamedCurve`](../type-aliases/NamedCurve.md)

The EC named curve identifier

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

---

### keyEncryptionAlgorithm()

> **keyEncryptionAlgorithm**(`encryptionParams`): [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts asymmetric encryption algorithm parameters to a key encryption algorithm identifier.

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Key encryption algorithm as an AlgorithmIdentifier

---

### sign()

> **sign**(`data`, `privateKeyInfo`, `algorithm`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Creates a digital signature for the given data.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The data to sign

##### privateKeyInfo

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The signer's private key

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The signature algorithm and parameters

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

Promise resolving to the signature bytes

---

### signatureAlgorithm()

> **signatureAlgorithm**(`algorithm`): `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Converts asymmetric encryption algorithm parameters to a signature algorithm identifier.

#### Parameters

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The asymmetric encryption algorithm parameters

#### Returns

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Signature algorithm as a Uint8Array<ArrayBuffer> or AlgorithmIdentifier

---

### toAsymmetricEncryptionAlgorithmParams()

> **toAsymmetricEncryptionAlgorithmParams**(`algorithm`, `publicKeyInfo?`): [`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Converts an ASN.1 algorithm identifier to asymmetric encryption algorithm parameters.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

Optional public key information for context

#### Returns

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Asymmetric encryption algorithm parameters

---

### toHashAlgorithm()

> **toHashAlgorithm**(`algorithm`): [`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

Converts an ASN.1 algorithm identifier to a hash algorithm.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

#### Returns

[`HashAlgorithm`](../type-aliases/HashAlgorithm.md)

The hash algorithm

---

### toSymmetricEncryptionAlgorithmParams()

> **toSymmetricEncryptionAlgorithmParams**(`algorithm`): [`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md)

Converts an ASN.1 algorithm identifier to symmetric encryption algorithm parameters.

#### Parameters

##### algorithm

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The ASN.1 algorithm identifier

#### Returns

[`SymmetricEncryptionAlgorithmParams`](../type-aliases/SymmetricEncryptionAlgorithmParams.md)

Symmetric encryption algorithm parameters

---

### verify()

> **verify**(`data`, `publicKeyInfo`, `signature`, `algorithm`): `Promise`\<`boolean`\>

Verifies a digital signature against the original data.

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`

The original data that was signed

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The signer's public key

##### signature

`Uint8Array<ArrayBuffer>`

The signature to verify

##### algorithm

[`AsymmetricEncryptionAlgorithmParams`](../type-aliases/AsymmetricEncryptionAlgorithmParams.md)

The signature algorithm and parameters

#### Returns

`Promise`\<`boolean`\>

Promise resolving to true if signature is valid
