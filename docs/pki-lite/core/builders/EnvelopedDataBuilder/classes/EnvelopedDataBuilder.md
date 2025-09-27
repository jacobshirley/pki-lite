[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/EnvelopedDataBuilder](../README.md) / EnvelopedDataBuilder

# Class: EnvelopedDataBuilder

Builder class for creating CMS EnvelopedData structures.

This builder allows setting the data to be encrypted, the content encryption algorithm,
and adding multiple recipients who can decrypt the data. It also supports including
certificates and revocation information in the originator info.

## Example

````typescript

const recipientCert1 = Certificate.fromPem(`-----BEGIN CERTIFICATE-----')
const recipientCert2 = Certificate.fromPem(`-----BEGIN CERTIFICATE-----')

const builder = new EnvelopedDataBuilder()
builder.setData("Secret message")
builder.setContentEncryptionAlgorithm({ type: 'AES_256_GCM', params: { nonce: randomBytes(12) } })
builder.addRecipient({ certificate: recipientCert1 })
builder.addRecipient({
    certificate: recipientCert2,
    keyEncryptionAlgorithm: {
        type: 'RSA_OAEP',
        params: { hash: 'SHA-384' }
    }
})
const envelopedData = await builder.build()
const der = envelopedData.toDer()

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`EnvelopedData`](../../../../pkcs7/EnvelopedData/classes/EnvelopedData.md)\>

## Constructors

### Constructor

> **new EnvelopedDataBuilder**(): `EnvelopedDataBuilder`

#### Returns

`EnvelopedDataBuilder`

## Properties

### certificates?

> `optional` **certificates**: [`CertificateChoices`](../../../../x509/CertificateChoices/type-aliases/CertificateChoices.md)[]

Optional certificates to include in originator info

***

### contentEncryptionAlgorithm?

> `optional` **contentEncryptionAlgorithm**: [`SymmetricEncryptionAlgorithmParams`](../../../crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

Algorithm used to encrypt the content

***

### contentType

> **contentType**: [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Content type identifier, defaults to PKCS#7 data

***

### crls

> **crls**: [`RevocationInfoChoice`](../../../../revocation/RevocationInfoChoice/type-aliases/RevocationInfoChoice.md)[] = `[]`

Certificate Revocation Lists to include

***

### data?

> `optional` **data**: `Uint8Array`\<`ArrayBufferLike`\>

The data to be encrypted

***

### recipients

> **recipients**: [`EnvelopedDataBuilderRecipient`](../type-aliases/EnvelopedDataBuilderRecipient.md)[] = `[]`

Recipients who can decrypt the enveloped data

***

### DEFAULT\_KEY\_ENCRYPTION\_ALGORITHM

> `readonly` `static` **DEFAULT\_KEY\_ENCRYPTION\_ALGORITHM**: [`KeyEncryptionAlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/KeyEncryptionAlgorithmIdentifier.md)

Default key encryption algorithm (RSA-OAEP with SHA-1).
Used when no specific key encryption algorithm is provided for a recipient.

## Accessors

### originatorInfo

#### Get Signature

> **get** **originatorInfo**(): `undefined` \| [`OriginatorInfo`](../../../../pkcs7/recipients/OriginatorInfo/classes/OriginatorInfo.md)

Gets the originator info containing certificates and CRLs.
Returns undefined if no certificates are present.

##### Returns

`undefined` \| [`OriginatorInfo`](../../../../pkcs7/recipients/OriginatorInfo/classes/OriginatorInfo.md)

OriginatorInfo or undefined

## Methods

### addCrl()

> **addCrl**(`crl`): `this`

Adds a Certificate Revocation List to the enveloped data.
CRLs can be used by recipients to verify certificate validity.

#### Parameters

##### crl

[`CertificateList`](../../../../x509/CertificateList/classes/CertificateList.md)

The certificate revocation list to include

#### Returns

`this`

This builder instance for method chaining

#### Example

```typescript
builder.addCrl(latestCrl)
````

---

### addOcsp()

> **addOcsp**(`ocsp`): `this`

Adds an OCSP response to the enveloped data for certificate status validation.
OCSP responses provide real-time certificate revocation status.

#### Parameters

##### ocsp

[`OCSPResponse`](../../../../ocsp/OCSPResponse/classes/OCSPResponse.md)

The OCSP response to include

#### Returns

`this`

This builder instance for method chaining

#### Example

```typescript
builder.addOcsp(ocspResponse)
```

---

### addRecipient()

> **addRecipient**(...`recipient`): `this`

Adds one or more recipients who can decrypt the enveloped data.
Each recipient's public key will be used to encrypt the content encryption key.

#### Parameters

##### recipient

...[`EnvelopedDataBuilderRecipient`](../type-aliases/EnvelopedDataBuilderRecipient.md)[]

One or more recipient configurations

#### Returns

`this`

This builder instance for method chaining

#### Example

```typescript
builder.addRecipient(
    { certificate: cert1 },
    {
        certificate: cert2,
        keyEncryptionAlgorithm: {
            type: 'RSA_OAEP',
            params: { hash: 'SHA-384' },
        },
    },
)
```

---

### build()

> **build**(): `Promise`\<[`EnvelopedData`](../../../../pkcs7/EnvelopedData/classes/EnvelopedData.md)\>

Builds the EnvelopedData structure by encrypting the content and creating recipient infos.

The build process:

1. Generates a random symmetric key for content encryption
2. Encrypts the data with the symmetric key
3. For each recipient, encrypts the symmetric key with their public key
4. Creates the final EnvelopedData structure

#### Returns

`Promise`\<[`EnvelopedData`](../../../../pkcs7/EnvelopedData/classes/EnvelopedData.md)\>

Promise resolving to the constructed EnvelopedData

#### Throws

Error if no data is set or no recipients are specified

#### Example

```typescript
const envelopedData = await builder
    .setData('Confidential document')
    .addRecipient({ certificate: recipientCert })
    .build()

// The enveloped data can now be transmitted securely
const der = envelopedData.toASN1().toDER()
```

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setContentEncryptionAlgorithm()

> **setContentEncryptionAlgorithm**(`algorithm`): `this`

Sets the symmetric encryption algorithm used to encrypt the content.
If not set, defaults to AES-256-CBC with a random IV.

#### Parameters

##### algorithm

[`SymmetricEncryptionAlgorithmParams`](../../../crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

The content encryption algorithm parameters

#### Returns

`this`

This builder instance for method chaining

#### Example

```typescript
builder.setContentEncryptionAlgorithm({
    type: 'AES_256_GCM',
    params: { nonce: crypto.getRandomValues(new Uint8Array(12)) },
})
```

---

### setContentType()

> **setContentType**(`type`): `this`

Sets the content type identifier for the encrypted data.

#### Parameters

##### type

The content type as ObjectIdentifier or string

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md) | [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Returns

`this`

This builder instance for method chaining

#### Example

```typescript
builder.setContentType('1.2.840.113549.1.7.1') // PKCS#7 data
builder.setContentType(
    new ObjectIdentifier({ value: '1.2.840.113549.1.9.16.1.4' }),
) // eContentTypes id-alg-pwri-kek
```

---

### setData()

> **setData**(`data`, `contentType?`): `this`

Sets the data to be encrypted and optionally the content type.

#### Parameters

##### data

The data to encrypt, either as bytes or string

`string` | `Uint8Array`\<`ArrayBufferLike`\>

##### contentType?

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md)

Optional content type identifier

#### Returns

`this`

This builder instance for method chaining

#### Example

```typescript
builder.setData('Secret message')
builder.setData(documentBytes, '1.2.840.113549.1.7.1') // PKCS#7 data
```
