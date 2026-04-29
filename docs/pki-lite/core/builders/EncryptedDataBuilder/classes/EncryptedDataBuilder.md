[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/EncryptedDataBuilder](../README.md) / EncryptedDataBuilder

# Class: EncryptedDataBuilder

Builder class for creating PKCS#7 EncryptedData structures.

Provides a fluent API for encrypting data. By default uses PBES2 (PBKDF2 + AES-256-CBC),
but can accept custom algorithms via setAlgorithm().

## Example

```typescript
// Using default PBES2 algorithm
const encryptedData = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(contentBytes)
    .setPassword('secret')
    .setIterations(2048)
    .build()

// Using custom algorithm
const customEncrypted = await EncryptedData.builder()
    .setContentType('DATA')
    .setData(contentBytes)
    .setPassword('secret')
    .setAlgorithm({
        type: 'AES_256_GCM',
        params: { nonce: randomIV },
    })
    .build()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`EncryptedData`](../../../../pkcs7/EncryptedData/classes/EncryptedData.md)\>

## Constructors

### Constructor

> **new EncryptedDataBuilder**(): `EncryptedDataBuilder`

#### Returns

`EncryptedDataBuilder`

## Methods

### build()

> **build**(): `Promise`\<[`EncryptedData`](../../../../pkcs7/EncryptedData/classes/EncryptedData.md)\>

Builds the EncryptedData structure.

#### Returns

`Promise`\<[`EncryptedData`](../../../../pkcs7/EncryptedData/classes/EncryptedData.md)\>

Promise resolving to the EncryptedData instance

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setAlgorithm()

> **setAlgorithm**(`algorithm`): `this`

Sets the encryption algorithm. Accepts either algorithm parameters or a pre-built algorithm identifier.
If not set, defaults to PBES2 (PBKDF2 + AES-256-CBC).

#### Parameters

##### algorithm

The encryption algorithm parameters or identifier

[`SymmetricEncryptionAlgorithmParams`](../../../crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md) | [`ContentEncryptionAlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/ContentEncryptionAlgorithmIdentifier.md)

#### Returns

`this`

This builder for chaining

---

### setContentType()

> **setContentType**(`type`): `this`

Sets the content type using a friendly name.

#### Parameters

##### type

The content type name

`"DATA"` | `"SIGNED_DATA"` | `"ENVELOPED_DATA"` | `"SIGNED_AND_ENVELOPED_DATA"` | `"DIGESTED_DATA"` | `"ENCRYPTED_DATA"` | `"AUTHENTICATED_DATA"` | `"AUTH_ENVELOPED_DATA"` | `"TST_INFO"`

#### Returns

`this`

This builder for chaining

---

### setContentTypeOid()

> **setContentTypeOid**(`type`): `this`

Sets the content type OID for the encrypted data.

#### Parameters

##### type

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md) | [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Returns

`this`

This builder for chaining

---

### setData()

> **setData**(`data`): `this`

Sets the data to encrypt.

#### Parameters

##### data

`Uint8Array`\<`ArrayBuffer`\>

The data bytes

#### Returns

`this`

This builder for chaining

---

### setIterations()

> **setIterations**(`iterations`): `this`

Sets the iteration count for PBKDF2. Defaults to 2048.

#### Parameters

##### iterations

`number`

The iteration count

#### Returns

`this`

This builder for chaining

---

### setIV()

> **setIV**(`iv`): `this`

Sets the IV for AES encryption. If not set, a random IV will be generated.

#### Parameters

##### iv

`Uint8Array`\<`ArrayBuffer`\>

The IV bytes

#### Returns

`this`

This builder for chaining

---

### setPassword()

> **setPassword**(`password`): `this`

Sets the password for encryption.

#### Parameters

##### password

The password (string or bytes)

`string` | `Uint8Array`\<`ArrayBuffer`\>

#### Returns

`this`

This builder for chaining

---

### setSalt()

> **setSalt**(`salt`): `this`

Sets the salt for PBKDF2. If not set, a random salt will be generated.

#### Parameters

##### salt

`Uint8Array`\<`ArrayBuffer`\>

The salt bytes

#### Returns

`this`

This builder for chaining
