[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/KeyGen](../README.md) / KeyGen

# Class: KeyGen

KeyGen class provides functionality to generate cryptographic key pairs.

This class leverages the configured cryptographic provider to create
key pairs for various algorithms such as RSA, ECDSA, and EdDSA. The
generated keys are returned in standard formats suitable for storage
and usage in cryptographic operations.

## Example

```typescript
// Generate an RSA key pair
const { privateKey, publicKey } = await KeyGen.generate({
    algorithm: 'RSA',
    params: {
        keySize: 2048,
        hash: 'SHA-256',
    },
})

// Or use convenience methods
const rsaPair = await KeyGen.generateRsaPair({ keySize: 2048 })
const ecPair = await KeyGen.generateEcPair({ namedCurve: 'P-256' })
```

## Constructors

### Constructor

> **new KeyGen**(): `KeyGen`

#### Returns

`KeyGen`

## Methods

### generate()

> `static` **generate**(`options`): `Promise`\<\{ `privateKey`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md); `publicKey`: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md); \}\>

Generates a new key pair.

#### Parameters

##### options

[`KeyPairGenOptions`](../../crypto/types/type-aliases/KeyPairGenOptions.md)

The key generation options

#### Returns

`Promise`\<\{ `privateKey`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md); `publicKey`: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md); \}\>

A PrivateKeyInfo containing the generated key pair

#### Example

```typescript
// Generate an ECDSA key pair using P-256 curve
const { privateKey, publicKey } = await KeyGen.generate({
    algorithm: 'EC',
    params: {
        namedCurve: 'P-256',
    },
})
```

---

### generateEcPair()

> `static` **generateEcPair**(`options?`): `Promise`\<\{ `privateKey`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md); `publicKey`: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md); \}\>

Generates an EC (Elliptic Curve) key pair with the specified curve.

#### Parameters

##### options?

EC key generation options (defaults: namedCurve='P-256')

###### namedCurve?

`"P-256"` \| `"P-384"` \| `"P-521"`

#### Returns

`Promise`\<\{ `privateKey`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md); `publicKey`: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md); \}\>

A PrivateKeyInfo containing the generated EC key pair

#### Example

```typescript
// Generate P-256 EC key pair (default)
const { privateKey, publicKey } = await KeyGen.generateEcPair()

// Generate P-384 EC key pair
const { privateKey, publicKey } = await KeyGen.generateEcPair({
    namedCurve: 'P-384',
})
```

---

### generateRsaPair()

> `static` **generateRsaPair**(`options?`): `Promise`\<\{ `privateKey`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md); `publicKey`: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md); \}\>

Generates an RSA key pair with the specified options.

#### Parameters

##### options?

RSA key generation options (defaults: keySize=2048, hash='SHA-256')

###### hash?

`"SHA-1"` \| `"SHA-256"` \| `"SHA-384"` \| `"SHA-512"`

###### keySize?

`number`

###### publicExponent?

`number`

#### Returns

`Promise`\<\{ `privateKey`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md); `publicKey`: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md); \}\>

A PrivateKeyInfo containing the generated RSA key pair

#### Example

```typescript
// Generate 2048-bit RSA key pair
const { privateKey, publicKey } = await KeyGen.generateRsaPair()

// Generate 4096-bit RSA key pair with SHA-512
const { privateKey, publicKey } = await KeyGen.generateRsaPair({
    keySize: 4096,
    hash: 'SHA-512',
})
```
