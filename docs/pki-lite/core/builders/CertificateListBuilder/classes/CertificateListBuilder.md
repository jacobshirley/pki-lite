[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/CertificateListBuilder](../README.md) / CertificateListBuilder

# Class: CertificateListBuilder

Builder class for creating X.509 Certificate Revocation Lists (CRLs).

Provides a fluent API for constructing CRLs with revoked certificates,
extensions, and signing them with a CA's private key.

## Example

```typescript
const crl = await CertificateList.builder()
    .setIssuer('CN=My CA, O=My Org')
    .setPrivateKey(caPrivateKey)
    .setThisUpdate(new Date())
    .setNextUpdate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
    .addRevokedCertificate({
        serialNumber: 12345,
        revocationDate: new Date(),
    })
    .build()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`CertificateList`](../../../../x509/CertificateList/classes/CertificateList.md)\>

## Constructors

### Constructor

> **new CertificateListBuilder**(): `CertificateListBuilder`

#### Returns

`CertificateListBuilder`

## Methods

### addExtension()

> **addExtension**(`extension`): `this`

Adds a CRL extension (e.g., CRL number, authority key identifier).

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

Adds multiple CRL extensions.

#### Parameters

##### extensions

...[`Extension`](../../../../x509/Extension/classes/Extension.md)[]

The extensions to add

#### Returns

`this`

This builder for chaining

---

### addRevokedCertificate()

> **addRevokedCertificate**(`entry`): `this`

Adds a revoked certificate entry.

#### Parameters

##### entry

Revoked certificate details, or a RevokedCertificate instance

[`RevokedCertificate`](../../../../x509/RevokedCertificate/classes/RevokedCertificate.md) | \{ `crlEntryExtensions?`: [`Extension`](../../../../x509/Extension/classes/Extension.md)[]; `revocationDate`: `Date`; `serialNumber`: `string` \| `number`; \}

#### Returns

`this`

This builder for chaining

#### Example

```typescript
builder.addRevokedCertificate({
    serialNumber: 12345,
    revocationDate: new Date(),
})
```

---

### build()

> **build**(): `Promise`\<[`CertificateList`](../../../../x509/CertificateList/classes/CertificateList.md)\>

Builds and signs the CRL.

#### Returns

`Promise`\<[`CertificateList`](../../../../x509/CertificateList/classes/CertificateList.md)\>

Promise resolving to the signed CertificateList

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### revokeCertificate()

> **revokeCertificate**(`certificate`, `revocationDate?`): `this`

Revokes a certificate by reference. Uses the certificate's serial number
and the current time as the revocation date if not provided.

#### Parameters

##### certificate

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

The certificate to revoke

##### revocationDate?

`Date`

The revocation date (defaults to now)

#### Returns

`this`

This builder for chaining

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

### setIssuer()

> **setIssuer**(`issuer`): `this`

Sets the CRL issuer (the CA name).

#### Parameters

##### issuer

Issuer DN as string or Name object

`string` | [`RDNSequence`](../../../../x509/RDNSequence/classes/RDNSequence.md)

#### Returns

`this`

This builder for chaining

---

### setIssuerFromCertificate()

> **setIssuerFromCertificate**(`caCertificate`): `this`

Sets the issuer from a CA certificate's subject.

#### Parameters

##### caCertificate

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

The CA certificate

#### Returns

`this`

This builder for chaining

---

### setNextUpdate()

> **setNextUpdate**(`date`): `this`

Sets the nextUpdate time (when the next CRL will be issued).
Defaults to 30 days after thisUpdate if not set.

#### Parameters

##### date

`Date`

The next update date

#### Returns

`this`

This builder for chaining

---

### setPrivateKey()

> **setPrivateKey**(`privateKey`): `this`

Sets the private key for signing the CRL.

#### Parameters

##### privateKey

[`PrivateKeyInfo`](../../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The CA's private key

#### Returns

`this`

This builder for chaining

---

### setThisUpdate()

> **setThisUpdate**(`date`): `this`

Sets the thisUpdate time (when this CRL was issued).
Defaults to current time if not set.

#### Parameters

##### date

`Date`

The issue date

#### Returns

`this`

This builder for chaining
