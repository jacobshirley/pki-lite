[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/SignedDataBuilder](../README.md) / SignedDataBuilder

# Class: SignedDataBuilder

Builder class for creating CMS/PKCS#7 SignedData structures.

This builder provides a fluent API for constructing digitally signed data
structures. It supports multiple signers, attached/detached signatures,
certificate chains, CRLs, and timestamping. The builder handles the
complexity of assembling all required components and calculating signatures.

## Example

```typescript
// Create attached signature (content included)
const signedData = await new SignedDataBuilder()
    .setData('Hello, World!')
    .addSigner({
        privateKeyInfo: signerPrivateKey,
        certificate: signerCert,
    })
    .addCertificate(caCert)
    .build()

// Create detached signature (content separate)
const detachedSignature = await new SignedDataBuilder()
    .setData(documentBytes)
    .setDetached(true)
    .addSigner({
        privateKeyInfo: signerPrivateKey,
        certificate: signerCert,
        tsa: { url: 'http://timestamp.example.com' },
    })
    .build()

// Multiple signers with custom attributes
const multiSigned = await new SignedDataBuilder()
    .setData(data)
    .addSigner({
        privateKeyInfo: signer1Key,
        certificate: signer1Cert,
        signedAttrs: [signingTimeAttr],
    })
    .addSigner({
        privateKeyInfo: signer2Key,
        certificate: signer2Cert,
    })
    .build()
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`SignedData`](../../../../pkcs7/SignedData/classes/SignedData.md)\>

## Constructors

### Constructor

> **new SignedDataBuilder**(): `SignedDataBuilder`

#### Returns

`SignedDataBuilder`

## Properties

### additionalCertificates

> **additionalCertificates**: [`CertificateChoices`](../../../../x509/CertificateChoices/type-aliases/CertificateChoices.md)[] = `[]`

Additional certificates to include (e.g., CA certificates).

---

### contentType

> **contentType**: [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Content type identifier for the data being signed.

---

### crls

> **crls**: [`RevocationInfoChoice`](../../../../revocation/RevocationInfoChoice/type-aliases/RevocationInfoChoice.md)[] = `[]`

Certificate Revocation Lists to include.

---

### data?

> `optional` **data**: `Uint8Array`\<`ArrayBufferLike`\>

The data to be signed (optional for detached signatures).

---

### detached()

> **detached**: (`detached`) => `SignedDataBuilder`

Alias for setDetached for more fluent API.

Configures whether to create a detached signature.

#### Parameters

##### detached

`boolean` = `true`

true for detached, false for attached (default: true)

#### Returns

`SignedDataBuilder`

This builder instance for chaining

---

### isDetached

> **isDetached**: `boolean` = `false`

Whether to create a detached signature (data not included).

---

### signers

> **signers**: [`SignedDataBuilderSigner`](../type-aliases/SignedDataBuilderSigner.md)[] = `[]`

Array of signers to include in the SignedData.

## Accessors

### allCertificates

#### Get Signature

> **get** **allCertificates**(): [`CertificateChoices`](../../../../x509/CertificateChoices/type-aliases/CertificateChoices.md)[]

##### Returns

[`CertificateChoices`](../../../../x509/CertificateChoices/type-aliases/CertificateChoices.md)[]

---

### encapContentInfo

#### Get Signature

> **get** **encapContentInfo**(): [`EncapsulatedContentInfo`](../../../../pkcs7/EncapsulatedContentInfo/classes/EncapsulatedContentInfo.md)

##### Returns

[`EncapsulatedContentInfo`](../../../../pkcs7/EncapsulatedContentInfo/classes/EncapsulatedContentInfo.md)

## Methods

### addCertificate()

> **addCertificate**(...`certs`): `this`

#### Parameters

##### certs

...[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)[]

#### Returns

`this`

---

### addCrl()

> **addCrl**(`crl`): `this`

#### Parameters

##### crl

[`CertificateList`](../../../../x509/CertificateList/classes/CertificateList.md)

#### Returns

`this`

---

### addOcsp()

> **addOcsp**(`ocsp`): `this`

#### Parameters

##### ocsp

[`OCSPResponse`](../../../../ocsp/OCSPResponse/classes/OCSPResponse.md)

#### Returns

`this`

---

### addOtherRevocationInfo()

> **addOtherRevocationInfo**(`crl`): `this`

#### Parameters

##### crl

[`OtherRevocationInfoFormat`](../../../../revocation/OtherRevocationInfoFormat/classes/OtherRevocationInfoFormat.md)

#### Returns

`this`

---

### addSigner()

> **addSigner**(`signer`): `this`

#### Parameters

##### signer

[`SignedDataBuilderSigner`](../type-aliases/SignedDataBuilderSigner.md)

#### Returns

`this`

---

### build()

> **build**(): `Promise`\<[`SignedData`](../../../../pkcs7/SignedData/classes/SignedData.md)\>

Builds and returns the constructed object asynchronously.

#### Returns

`Promise`\<[`SignedData`](../../../../pkcs7/SignedData/classes/SignedData.md)\>

Promise resolving to the constructed object of type T

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setContentType()

> **setContentType**(`type`): `this`

Sets the content type for the data being signed.

#### Parameters

##### type

Content type identifier or string

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md) | [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Returns

`this`

This builder instance for chaining

---

### setData()

> **setData**(`data`, `contentType?`): `this`

Sets the data to be signed and optionally the content type.

#### Parameters

##### data

The data as bytes or string

`string` | `Uint8Array`\<`ArrayBufferLike`\>

##### contentType?

[`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Optional content type identifier

#### Returns

`this`

This builder instance for chaining

---

### setDetached()

> **setDetached**(`detached`): `SignedDataBuilder`

Configures whether to create a detached signature.

#### Parameters

##### detached

`boolean` = `true`

true for detached, false for attached (default: true)

#### Returns

`SignedDataBuilder`

This builder instance for chaining
