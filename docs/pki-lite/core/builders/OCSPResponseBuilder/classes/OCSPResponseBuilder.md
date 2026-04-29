[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/OCSPResponseBuilder](../README.md) / OCSPResponseBuilder

# Class: OCSPResponseBuilder

Builder class for creating OCSP Responses.

Provides a fluent API for constructing OCSP responses with multiple certificate
statuses, responder identification, extensions, and signatures.

## Example

```typescript
const response = await OCSPResponse.builder()
    .setResponderByName('CN=OCSP Responder')
    .setPrivateKey(responderKey)
    .addResponse(issuerCert, cert1, 'good')
    .addResponse(issuerCert, cert2, 'revoked', {
        revocationTime: new Date(),
        revocationReason: 0,
    })
    .build()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`OCSPResponse`](../../../../ocsp/OCSPResponse/classes/OCSPResponse.md)\>

## Constructors

### Constructor

> **new OCSPResponseBuilder**(): `OCSPResponseBuilder`

#### Returns

`OCSPResponseBuilder`

## Methods

### addCertificate()

> **addCertificate**(`certificate`): `this`

Adds a certificate to include in the response (for chain validation).

#### Parameters

##### certificate

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

The certificate to include

#### Returns

`this`

This builder for chaining

---

### addCertificateResponse()

> **addCertificateResponse**(`options`): `this`

Adds a single certificate response.

#### Parameters

##### options

Certificate response details

###### certID?

[`CertID`](../../../../ocsp/CertID/classes/CertID.md)

###### certificate?

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

###### issuerCertificate?

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

###### nextUpdate?

`Date`

###### revocationReason?

`number`

###### revocationTime?

`Date`

###### singleExtensions?

[`Extension`](../../../../x509/Extension/classes/Extension.md)[]

###### status

`"good"` \| `"revoked"` \| `"unknown"`

###### thisUpdate?

`Date`

#### Returns

`this`

This builder for chaining

---

### addResponse()

> **addResponse**(`issuerOrCertID`, `certificateOrStatus`, `statusOrOptions?`, `options?`): `this`

Adds a certificate status response.

#### Parameters

##### issuerOrCertID

The issuer certificate (when using Certificate) or CertID directly

[`CertID`](../../../../ocsp/CertID/classes/CertID.md) | [`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

##### certificateOrStatus

The subject certificate (when using Certificate) or status (when using CertID)

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md) | `"good"` | `"revoked"` | `"unknown"`

##### statusOrOptions?

The status (when using Certificate) or options (when using CertID)

`"good"` | `"revoked"` | `"unknown"` | \{ `nextUpdate?`: `Date`; `revocationReason?`: `number`; `revocationTime?`: `Date`; `singleExtensions?`: [`Extension`](../../../../x509/Extension/classes/Extension.md)[]; `thisUpdate?`: `Date`; \}

##### options?

Optional parameters (only when using Certificate)

###### nextUpdate?

`Date`

###### revocationReason?

`number`

###### revocationTime?

`Date`

###### singleExtensions?

[`Extension`](../../../../x509/Extension/classes/Extension.md)[]

###### thisUpdate?

`Date`

#### Returns

`this`

This builder for chaining

#### Example

```typescript
// With certificates
builder
    .addResponse(issuerCert, cert1, 'good')
    .addResponse(issuerCert, cert2, 'revoked', {
        revocationTime: new Date(),
        revocationReason: 0,
    })

// With CertID
builder.addResponse(certID, 'good')
```

---

### addResponseExtension()

> **addResponseExtension**(`extension`): `this`

Adds a response extension (applies to the entire response).

#### Parameters

##### extension

[`Extension`](../../../../x509/Extension/classes/Extension.md)

The extension to add

#### Returns

`this`

This builder for chaining

---

### build()

> **build**(): `Promise`\<[`OCSPResponse`](../../../../ocsp/OCSPResponse/classes/OCSPResponse.md)\>

Builds and signs the OCSP response.

#### Returns

`Promise`\<[`OCSPResponse`](../../../../ocsp/OCSPResponse/classes/OCSPResponse.md)\>

Promise resolving to the signed OCSPResponse

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setAlgorithm()

> **setAlgorithm**(`algorithm`): `this`

Sets the signature algorithm.

#### Parameters

##### algorithm

Algorithm parameters or SignatureAlgorithmIdentifier

[`SignatureAlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/SignatureAlgorithmIdentifier.md) | [`AsymmetricEncryptionAlgorithmParams`](../../../crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

`this`

This builder for chaining

---

### setPrivateKey()

> **setPrivateKey**(`privateKey`): `this`

Sets the private key for signing the response.

#### Parameters

##### privateKey

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The responder's private key

#### Returns

`this`

This builder for chaining

---

### setProducedAt()

> **setProducedAt**(`date`): `this`

Sets the producedAt time (when this response was generated).
Defaults to current time if not set.

#### Parameters

##### date

`Date`

The production date

#### Returns

`this`

This builder for chaining

---

### setResponderByKeyHash()

> **setResponderByKeyHash**(`keyHash`): `this`

Sets the responder ID using a key hash (byKey).

#### Parameters

##### keyHash

`Uint8Array`\<`ArrayBuffer`\>

SHA-1 hash of the responder's public key

#### Returns

`this`

This builder for chaining

---

### setResponderByName()

> **setResponderByName**(`name`): `this`

Sets the responder ID using a name (byName).

#### Parameters

##### name

The responder's distinguished name

`string` | [`RDNSequence`](../../../../x509/RDNSequence/classes/RDNSequence.md)

#### Returns

`this`

This builder for chaining

---

### setResponderFromCertificate()

> **setResponderFromCertificate**(`certificate`): `this`

Sets the responder ID from a certificate's subject.

#### Parameters

##### certificate

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

The responder's certificate

#### Returns

`this`

This builder for chaining

---

### setResponseStatus()

> **setResponseStatus**(`status`): `this`

Sets the overall response status.

#### Parameters

##### status

The OCSP response status

`number` | [`OCSPResponseStatus`](../../../../ocsp/OCSPResponseStatus/classes/OCSPResponseStatus.md)

#### Returns

`this`

This builder for chaining
