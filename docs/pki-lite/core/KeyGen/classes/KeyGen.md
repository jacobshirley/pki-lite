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

````typescript
// Generate an RSA key pair
const { privateKey, publicKey } = await KeyGen.generate({
    algorithm: 'RSA',
    params: {
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: 'SHA-256'
    }
})

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
    algorithm: 'ECDSA',
    params: {
        namedCurve: 'P-256',
        hash: 'SHA-256'
    }
})
````
