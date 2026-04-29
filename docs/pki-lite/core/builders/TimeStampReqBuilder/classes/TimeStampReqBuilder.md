[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/TimeStampReqBuilder](../README.md) / TimeStampReqBuilder

# Class: TimeStampReqBuilder

Builder class for creating RFC 3161 Time-Stamp Requests.

Provides a fluent API for constructing TimeStampReq objects, including
automatic hashing of input data.

## Example

```typescript
// Build from raw data (hash computed automatically)
const tsReq = await TimeStampReq.builder()
    .setData(documentBytes)
    .setHashAlgorithm('SHA-256')
    .setCertReq(true)
    .setNonce(crypto.getRandomValues(new Uint8Array(8)))
    .build()

// Send to TSA
const response = await tsReq.request({ url: 'https://freetsa.org/tsr' })
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`TimeStampReq`](../../../../timestamp/TimeStampReq/classes/TimeStampReq.md)\>

## Constructors

### Constructor

> **new TimeStampReqBuilder**(): `TimeStampReqBuilder`

#### Returns

`TimeStampReqBuilder`

## Methods

### addExtension()

> **addExtension**(`extension`): `this`

Adds a request extension.

#### Parameters

##### extension

[`Extension`](../../../../x509/Extension/classes/Extension.md)

The extension to add

#### Returns

`this`

This builder for chaining

---

### build()

> **build**(): `Promise`\<[`TimeStampReq`](../../../../timestamp/TimeStampReq/classes/TimeStampReq.md)\>

Builds the timestamp request, computing the message imprint hash if
data was provided via setData().

#### Returns

`Promise`\<[`TimeStampReq`](../../../../timestamp/TimeStampReq/classes/TimeStampReq.md)\>

Promise resolving to the TimeStampReq

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setCertReq()

> **setCertReq**(`certReq`): `this`

Sets whether to request the TSA certificate in the response.

#### Parameters

##### certReq

`boolean` = `true`

Whether to request the TSA certificate

#### Returns

`this`

This builder for chaining

---

### setData()

> **setData**(`data`): `this`

Sets the data to be timestamped. The hash will be computed automatically
during build() using the configured hash algorithm.

#### Parameters

##### data

The data to timestamp (raw bytes or string)

`string` | `Uint8Array`\<`ArrayBuffer`\>

#### Returns

`this`

This builder for chaining

---

### setHashAlgorithm()

> **setHashAlgorithm**(`hash`): `this`

Sets the hash algorithm used to compute the message imprint.
Only used when setData() is provided. Defaults to 'SHA-256'.

#### Parameters

##### hash

[`HashAlgorithm`](../../../crypto/types/type-aliases/HashAlgorithm.md)

The hash algorithm

#### Returns

`this`

This builder for chaining

---

### setMessageImprint()

> **setMessageImprint**(`messageImprint`): `this`

Sets a pre-computed message imprint, bypassing automatic hashing.

#### Parameters

##### messageImprint

[`MessageImprint`](../../../../timestamp/MessageImprint/classes/MessageImprint.md)

The message imprint

#### Returns

`this`

This builder for chaining

---

### setNonce()

> **setNonce**(`nonce`): `this`

Sets the nonce for replay protection.

#### Parameters

##### nonce

`Uint8Array`\<`ArrayBuffer`\>

The nonce bytes (typically 8-16 random bytes)

#### Returns

`this`

This builder for chaining

---

### setRandomNonce()

> **setRandomNonce**(`byteLength`): `this`

Generates and sets a random nonce for replay protection.

#### Parameters

##### byteLength

`number` = `8`

The length of the random nonce (default 8)

#### Returns

`this`

This builder for chaining

---

### setReqPolicy()

> **setReqPolicy**(`policy`): `this`

Sets the requested TSA policy OID.

#### Parameters

##### policy

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md)

The TSA policy identifier

#### Returns

`this`

This builder for chaining

---

### setVersion()

> **setVersion**(`version`): `this`

Sets the protocol version. Defaults to 1.

#### Parameters

##### version

`number`

The protocol version

#### Returns

`this`

This builder for chaining
