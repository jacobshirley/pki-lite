[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/CertificateBuilder](../README.md) / CertificateBuilder

# Class: CertificateBuilder

Builder class for creating X.509 certificates.

This builder provides a fluent API for constructing certificates with
various options including subject, issuer, validity period, extensions,
and more. It supports both self-signed and CA-signed certificates.

## Example

```typescript
// Create a self-signed certificate
const cert = await Certificate.builder()
    .setSubject('CN=Test Certificate, O=My Org, C=US')
    .setPublicKey(publicKey)
    .setPrivateKey(privateKey)
    .setValidityPeriod(new Date('2024-01-01'), new Date('2025-01-01'))
    .addExtension(basicConstraintsExt)
    .selfSign()

// Create a CA-signed certificate
const cert = await Certificate.builder()
    .setSubject('CN=User Certificate')
    .setPublicKey(userPublicKey)
    .setIssuer(caCert)
    .setIssuerPrivateKey(caPrivateKey)
    .setSerialNumber(generateSerial())
    .setValidityPeriod(notBefore, notAfter)
    .sign()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

## Constructors

### Constructor

> **new CertificateBuilder**(): `CertificateBuilder`

#### Returns

`CertificateBuilder`

## Methods

### addAuthorityKeyIdentifier()

> **addAuthorityKeyIdentifier**(`keyIdentifier`): `this`

Adds an Authority Key Identifier extension to the certificate.

#### Parameters

##### keyIdentifier

`Uint8Array`\<`ArrayBuffer`\>

The authority key identifier bytes

#### Returns

`this`

This builder for chaining

---

### addBasicConstraints()

> **addBasicConstraints**(`cA`, `pathLenConstraint?`): `this`

Adds a Basic Constraints extension to the certificate.

#### Parameters

##### cA

`boolean`

Whether this is a CA certificate

##### pathLenConstraint?

`number`

Optional path length constraint

#### Returns

`this`

This builder for chaining

#### Example

```typescript
// CA certificate with path length 1
builder.addBasicConstraints(true, 1)

// End-entity certificate
builder.addBasicConstraints(false)
```

---

### addExtendedKeyUsage()

> **addExtendedKeyUsage**(`options`): `this`

Adds an Extended Key Usage extension to the certificate.

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

Adds an extension to the certificate.

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

Adds multiple extensions to the certificate.

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

Adds a Key Usage extension to the certificate.

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

Adds a Subject Alternative Name extension to the certificate.
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

// Mix strings and GeneralName objects
builder.addSubjectAltName(
    'example.com',
    new GeneralName.rfc822Name({ value: 'admin@example.com' }),
)
```

---

### addSubjectKeyIdentifier()

> **addSubjectKeyIdentifier**(`keyIdentifier`): `this`

Adds a Subject Key Identifier extension to the certificate.

#### Parameters

##### keyIdentifier

`Uint8Array`\<`ArrayBuffer`\>

The key identifier bytes

#### Returns

`this`

This builder for chaining

---

### build()

> **build**(): `Promise`\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

Alias for sign() to match the AsyncBuilder interface.
Builds a CA-signed certificate, or self-signed if no issuer is set.

#### Returns

`Promise`\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

Promise resolving to the signed certificate

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### generateSerialNumber()

> **generateSerialNumber**(): `this`

Generates a random serial number.

#### Returns

`this`

This builder for chaining

---

### selfSign()

> **selfSign**(): `Promise`\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

Builds and signs a self-signed certificate.

#### Returns

`Promise`\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

Promise resolving to the signed certificate

#### Throws

Error if required fields are missing

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

// Or using a SignatureAlgorithmIdentifier
builder.setAlgorithm(
    AlgorithmIdentifier.signatureAlgorithm({
        type: 'RSA_PSS',
        params: { hash: 'SHA-512', saltLength: 64 },
    }),
)
```

---

### setIssuer()

> **setIssuer**(`issuer`): `this`

Sets the issuer for the certificate.
For self-signed certificates, this will be set to match the subject.

#### Parameters

##### issuer

Issuer DN as string, Name object, or Certificate

`string` | [`RDNSequence`](../../../../x509/RDNSequence/classes/RDNSequence.md) | [`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

#### Returns

`this`

This builder for chaining

---

### setIssuerPrivateKey()

> **setIssuerPrivateKey**(`privateKey`): `this`

Sets the issuer's private key for signing (for CA-signed certificates).

#### Parameters

##### privateKey

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The issuer's private key

#### Returns

`this`

This builder for chaining

---

### setPrivateKey()

> **setPrivateKey**(`privateKey`): `this`

Sets the private key for signing (for self-signed certificates).

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

### setSerialNumber()

> **setSerialNumber**(`serialNumber`): `this`

Sets the serial number for the certificate.

#### Parameters

##### serialNumber

Serial number as bytes, number, or string

`string` | `number` | `Uint8Array`\<`ArrayBuffer`\>

#### Returns

`this`

This builder for chaining

---

### setSubject()

> **setSubject**(`subject`): `this`

Sets the subject distinguished name for the certificate.

#### Parameters

##### subject

Subject DN as string or Name object

`string` | [`RDNSequence`](../../../../x509/RDNSequence/classes/RDNSequence.md)

#### Returns

`this`

This builder for chaining

---

### setValidityDays()

> **setValidityDays**(`days`): `this`

Sets the validity period in days from now.

#### Parameters

##### days

`number`

Number of days the certificate should be valid

#### Returns

`this`

This builder for chaining

---

### setValidityPeriod()

> **setValidityPeriod**(`notBefore`, `notAfter`): `this`

Sets the validity period for the certificate.

#### Parameters

##### notBefore

`Date`

Start of validity period

##### notAfter

`Date`

End of validity period

#### Returns

`this`

This builder for chaining

---

### setVersion()

> **setVersion**(`version`): `this`

Sets the certificate version.

#### Parameters

##### version

`number`

Certificate version (0 = v1, 1 = v2, 2 = v3)

#### Returns

`this`

This builder for chaining

---

### sign()

> **sign**(): `Promise`\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

Builds and signs a certificate with the specified issuer.

#### Returns

`Promise`\<[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)\>

Promise resolving to the signed certificate

#### Throws

Error if required fields are missing
