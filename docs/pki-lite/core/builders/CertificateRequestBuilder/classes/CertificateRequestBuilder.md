[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/CertificateRequestBuilder](../README.md) / CertificateRequestBuilder

# Class: CertificateRequestBuilder

Builder class for creating PKCS#10 certificate signing requests (CSRs).

This builder provides a fluent API for constructing CSRs with
various options including subject, extensions, and signature algorithm.

## Example

```typescript
// Create a simple CSR
const csr = await CertificateRequest.builder()
    .setSubject('CN=example.com, O=My Org, C=US')
    .setPublicKey(publicKey)
    .setPrivateKey(privateKey)
    .addKeyUsage({ digitalSignature: true, keyEncipherment: true })
    .addSubjectAltName('example.com', '*.example.com')
    .build()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`CertificateRequest`](../../../../x509/CertificateRequest/classes/CertificateRequest.md)\>

## Constructors

### Constructor

> **new CertificateRequestBuilder**(): `CertificateRequestBuilder`

#### Returns

`CertificateRequestBuilder`

## Methods

### addExtendedKeyUsage()

> **addExtendedKeyUsage**(`options`): `this`

Adds an Extended Key Usage extension to the CSR.

#### Parameters

##### options

`object` & `object`

Extended key usage purposes

#### Returns

`this`

This builder for chaining

#### Example

```typescript
builder.addExtendedKeyUsage({
    serverAuth: true,
    clientAuth: true,
})
```

---

### addExtension()

> **addExtension**(`extension`): `this`

Adds an extension to the CSR.
Extensions are included in the extensionRequest attribute.

#### Parameters

##### extension

[`Extension`](../../../../x509/Extension/classes/Extension.md)

The extension to add

#### Returns

`this`

This builder for chaining

---

### addExtensions()

> **addExtensions**(...`extensions`): `this`

Adds multiple extensions to the CSR.

#### Parameters

##### extensions

...[`Extension`](../../../../x509/Extension/classes/Extension.md)[]

Array of extensions to add

#### Returns

`this`

This builder for chaining

---

### addKeyUsage()

> **addKeyUsage**(`options`): `this`

Adds a Key Usage extension to the CSR.

#### Parameters

##### options

[`KeyUsageOptions`](../../../../x509/extensions/KeyUsage/interfaces/KeyUsageOptions.md)

Key usage flags

#### Returns

`this`

This builder for chaining

#### Example

```typescript
builder.addKeyUsage({
    digitalSignature: true,
    keyEncipherment: true,
})
```

---

### addSubjectAltName()

> **addSubjectAltName**(...`altNames`): `this`

Adds a Subject Alternative Name extension to the CSR.
Strings are automatically converted to DNS names.

#### Parameters

##### altNames

...(`string` \| [`GeneralName`](../../../../x509/GeneralName/type-aliases/GeneralName.md))[]

Alternative names for the subject (strings or GeneralName objects)

#### Returns

`this`

This builder for chaining

#### Example

```typescript
// Simple DNS names as strings
builder.addSubjectAltName('example.com', '*.example.com')

// Or use GeneralName objects for other types
builder.addSubjectAltName(
    new GeneralName.dNSName({ value: 'example.com' }),
    new GeneralName.rfc822Name({ value: 'admin@example.com' }),
)
```

---

### build()

> **build**(): `Promise`\<[`CertificateRequest`](../../../../x509/CertificateRequest/classes/CertificateRequest.md)\>

Builds and signs the certificate signing request.

#### Returns

`Promise`\<[`CertificateRequest`](../../../../x509/CertificateRequest/classes/CertificateRequest.md)\>

Promise resolving to the signed CSR

#### Throws

Error if required fields are missing

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

#### Example

```typescript
// Using algorithm parameters
builder.setAlgorithm({
    type: 'ECDSA',
    params: { namedCurve: 'P-256', hash: 'SHA-256' },
})
```

---

### setPrivateKey()

> **setPrivateKey**(`privateKey`): `this`

Sets the private key for signing the CSR.

#### Parameters

##### privateKey

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The private key

#### Returns

`this`

This builder for chaining

---

### setPublicKey()

> **setPublicKey**(`publicKey`): `this`

Sets the subject's public key.

#### Parameters

##### publicKey

[`SubjectPublicKeyInfo`](../../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

The subject's public key

#### Returns

`this`

This builder for chaining

---

### setSubject()

> **setSubject**(`subject`): `this`

Sets the subject distinguished name for the CSR.

#### Parameters

##### subject

Subject DN as string or Name object

`string` | [`RDNSequence`](../../../../x509/RDNSequence/classes/RDNSequence.md)

#### Returns

`this`

This builder for chaining
