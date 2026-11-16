[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/AuthEnvelopedDataBuilder](../README.md) / AuthEnvelopedDataBuilder

# Class: AuthEnvelopedDataBuilder

Builder for CMS AuthEnvelopedData structures (RFC 5083): like EnvelopedData, but the
content is encrypted with AES-GCM, so it is also authenticated. The authentication
tag is stored as `mac`, and any authenticated attributes are covered by it as
additional authenticated data.

## Asn

```asn
AuthEnvelopedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     authEncryptedContentInfo EncryptedContentInfo,
     authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
     mac MessageAuthenticationCode,
     unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL
}
```

## Example

```typescript
const authEnvelopedData = await AuthEnvelopedData.builder()
    .setData('Confidential message')
    .addRecipient({ certificate: recipientCert })
    .build()

const plaintext = await authEnvelopedData.decrypt(recipientPrivateKey)
```

## See

RFC 5083 - Cryptographic Message Syntax (CMS) Authenticated-Enveloped-Data Content Type

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`AuthEnvelopedData`](../../../../pkcs7/AuthEnvelopedData/classes/AuthEnvelopedData.md)\>

## Constructors

### Constructor

> **new AuthEnvelopedDataBuilder**(): `AuthEnvelopedDataBuilder`

#### Returns

`AuthEnvelopedDataBuilder`

## Properties

### authAttrs

> **authAttrs**: [`Attribute`](../../../../x509/Attribute/classes/Attribute.md)[] = `[]`

Authenticated attributes, covered by the authentication tag

---

### contentEncryptionAlgorithm?

> `optional` **contentEncryptionAlgorithm**: [`AuthEnvelopedDataCipher`](../type-aliases/AuthEnvelopedDataCipher.md)

The AES-GCM cipher and its nonce / tag length; defaults to AES-256-GCM

---

### contentType

> **contentType**: [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Content type identifier, defaults to PKCS#7 data

---

### data?

> `optional` **data**: `Uint8Array`\<`ArrayBuffer`\>

The data to be encrypted

---

### recipients

> **recipients**: [`EnvelopedDataBuilderRecipient`](../../EnvelopedDataBuilder/type-aliases/EnvelopedDataBuilderRecipient.md)[] = `[]`

Recipients who can decrypt the data

---

### unauthAttrs

> **unauthAttrs**: [`Attribute`](../../../../x509/Attribute/classes/Attribute.md)[] = `[]`

Unauthenticated attributes

## Methods

### addAuthenticatedAttribute()

> **addAuthenticatedAttribute**(...`attributes`): `this`

Adds attributes that are authenticated along with the content.

#### Parameters

##### attributes

...[`Attribute`](../../../../x509/Attribute/classes/Attribute.md)[]

#### Returns

`this`

---

### addRecipient()

> **addRecipient**(...`recipient`): `this`

#### Parameters

##### recipient

...[`EnvelopedDataBuilderRecipient`](../../EnvelopedDataBuilder/type-aliases/EnvelopedDataBuilderRecipient.md)[]

#### Returns

`this`

---

### addUnauthenticatedAttribute()

> **addUnauthenticatedAttribute**(...`attributes`): `this`

#### Parameters

##### attributes

...[`Attribute`](../../../../x509/Attribute/classes/Attribute.md)[]

#### Returns

`this`

---

### build()

> **build**(): `Promise`\<[`AuthEnvelopedData`](../../../../pkcs7/AuthEnvelopedData/classes/AuthEnvelopedData.md)\>

Encrypts the data and creates the recipient infos.

#### Returns

`Promise`\<[`AuthEnvelopedData`](../../../../pkcs7/AuthEnvelopedData/classes/AuthEnvelopedData.md)\>

#### Throws

Error if no data or no recipient is set, or the cipher is not AES-GCM

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setContentEncryptionAlgorithm()

> **setContentEncryptionAlgorithm**(`algorithm`): `this`

Sets the AES-GCM cipher. `nonce` is the IV (12 bytes recommended) and `icvLen` the
authentication tag length in bytes (12 to 16, default 16).

#### Parameters

##### algorithm

[`AuthEnvelopedDataCipher`](../type-aliases/AuthEnvelopedDataCipher.md)

#### Returns

`this`

#### Example

```typescript
builder.setContentEncryptionAlgorithm({
    type: 'AES_128_GCM',
    params: { nonce: crypto.getRandomValues(new Uint8Array(12)), icvLen: 16 },
})
```

---

### setContentType()

> **setContentType**(`type`): `this`

#### Parameters

##### type

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md) | [`ObjectIdentifier`](../../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Returns

`this`

---

### setData()

> **setData**(`data`, `contentType?`): `this`

Sets the data to be encrypted and optionally the content type.

#### Parameters

##### data

`string` | `Uint8Array`\<`ArrayBuffer`\>

##### contentType?

[`ObjectIdentifierString`](../../../PkiBase/type-aliases/ObjectIdentifierString.md)

#### Returns

`this`
