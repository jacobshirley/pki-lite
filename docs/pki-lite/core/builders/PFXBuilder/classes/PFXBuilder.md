[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/PFXBuilder](../README.md) / PFXBuilder

# Class: PFXBuilder

Builder class for creating PKCS#12 (PFX) files.

Provides a fluent API for assembling certificates and private keys into
a password-protected PKCS#12 container. Uses PBES2 (PBKDF2 + AES-256-CBC)
for encryption and HMAC-SHA-256 with PKCS#12 password-based key derivation
(RFC 7292 Appendix B) for the MAC.

## Example

```typescript
const pfx = await PFX.builder()
    .addCertificate(clientCert)
    .addCertificate(caCert)
    .addPrivateKey(privateKey)
    .setPassword('s3cret')
    .setFriendlyName('My Identity')
    .build()

const pem = pfx.toPem()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`PFX`](../../../../pkcs12/PFX/classes/PFX.md)\>

## Constructors

### Constructor

> **new PFXBuilder**(): `PFXBuilder`

#### Returns

`PFXBuilder`

## Methods

### addCertificate()

> **addCertificate**(...`certificates`): `this`

Adds a certificate to the PFX. Can be called multiple times to add a chain.

#### Parameters

##### certificates

...[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)[]

One or more certificates

#### Returns

`this`

This builder for chaining

---

### addPrivateKey()

> **addPrivateKey**(...`privateKeys`): `this`

Adds a private key to the PFX. The key will be password-encrypted.

#### Parameters

##### privateKeys

...[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)[]

One or more private keys

#### Returns

`this`

This builder for chaining

---

### build()

> **build**(): `Promise`\<[`PFX`](../../../../pkcs12/PFX/classes/PFX.md)\>

Builds the PFX container.

#### Returns

`Promise`\<[`PFX`](../../../../pkcs12/PFX/classes/PFX.md)\>

Promise resolving to the PFX instance

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setFriendlyName()

> **setFriendlyName**(`friendlyName`): `this`

Sets an optional friendly name attached to the certificate/key bags.

#### Parameters

##### friendlyName

`string`

The friendly name

#### Returns

`this`

This builder for chaining

---

### setIterations()

> **setIterations**(`iterations`): `this`

Sets the number of iterations used by PBKDF2 and the MAC derivation.
Defaults to 2048.

#### Parameters

##### iterations

`number`

Iteration count

#### Returns

`this`

This builder for chaining

---

### setPassword()

> **setPassword**(`password`): `this`

Sets the password used to encrypt the private keys and compute the MAC.

#### Parameters

##### password

The password (string or bytes)

`string` | `Uint8Array`\<`ArrayBuffer`\>

#### Returns

`this`

This builder for chaining
