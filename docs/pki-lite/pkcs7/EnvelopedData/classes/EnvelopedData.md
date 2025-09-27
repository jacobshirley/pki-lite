[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/EnvelopedData](../README.md) / EnvelopedData

# Class: EnvelopedData

Represents a CMS EnvelopedData structure as defined in RFC 5652.

## Asn

```asn
EnvelopedData ::= SEQUENCE {
    version CMSVersion,
    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo,
    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
}
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`EnvelopedData`\>

## Constructors

### Constructor

> **new EnvelopedData**(`options`): `EnvelopedData`

Creates a new EnvelopedData instance.

#### Parameters

##### options

###### encryptedContentInfo

[`EncryptedContentInfo`](../../EncryptedContentInfo/classes/EncryptedContentInfo.md)

###### originatorInfo?

[`OriginatorInfo`](../../recipients/OriginatorInfo/classes/OriginatorInfo.md)

###### recipientInfos

[`RecipientInfo`](../../recipients/RecipientInfo/type-aliases/RecipientInfo.md)[]

###### unprotectedAttrs?

[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

###### version

`number`

#### Returns

`EnvelopedData`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### encryptedContentInfo

> **encryptedContentInfo**: [`EncryptedContentInfo`](../../EncryptedContentInfo/classes/EncryptedContentInfo.md)

The encrypted content and associated parameters.

---

### originatorInfo?

> `optional` **originatorInfo**: [`OriginatorInfo`](../../recipients/OriginatorInfo/classes/OriginatorInfo.md)

Optional information about the originator.

---

### recipientInfos

> **recipientInfos**: `RecipientInfos`

A collection of per-recipient information.

---

### unprotectedAttrs?

> `optional` **unprotectedAttrs**: [`Attributes`](../../../x509/Attributes/classes/Attributes.md)

Optional unprotected attributes.

---

### version

> **version**: `number`

The version of the EnvelopedData structure.

---

### RecipientInfos

> `static` **RecipientInfos**: _typeof_ `RecipientInfos`

Represents a set of RecipientInfo structures.

#### Asn

```
RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
```

---

### UnprotectedAttributes

> `static` **UnprotectedAttributes**: _typeof_ [`Attributes`](../../../x509/Attributes/classes/Attributes.md)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`pemHeader`](../../../core/PkiBase/classes/PkiBase.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`pkiType`](../../../core/PkiBase/classes/PkiBase.md#pkitype)

## Methods

### addCrl()

> **addCrl**(`crl`): `void`

#### Parameters

##### crl

[`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md)

#### Returns

`void`

---

### addOcsp()

> **addOcsp**(`OCSP`): `void`

#### Parameters

##### OCSP

[`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)

#### Returns

`void`

---

### decrypt()

> **decrypt**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

#### Parameters

##### privateKey

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### equals()

> **equals**(`other`): `boolean`

Compares this PKI object with another for equality.
Two objects are considered equal if their DER encodings are identical.

#### Parameters

##### other

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\>

The other PKI object to compare with

#### Returns

`boolean`

true if the objects are equal, false otherwise

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`equals`](../../../core/PkiBase/classes/PkiBase.md#equals)

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this object as a different PKI type.
Useful for converting between related PKI structures.

#### Type Parameters

##### T

`T`

The target type to parse as

#### Parameters

##### type

[`ParseableAsn1`](../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`parseAs`](../../../core/PkiBase/classes/PkiBase.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts the EnvelopedData to an ASN.1 structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toCms()

> **toCms**(): [`ContentInfo`](../../ContentInfo/classes/ContentInfo.md)

#### Returns

[`ContentInfo`](../../ContentInfo/classes/ContentInfo.md)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`

The DER-encoded bytes of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toDer`](../../../core/PkiBase/classes/PkiBase.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this object.
By default, returns the same as toString(), but subclasses can override
for more user-friendly output.

#### Returns

`string`

A human-readable string representation

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toHumanString`](../../../core/PkiBase/classes/PkiBase.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toJSON`](../../../core/PkiBase/classes/PkiBase.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toPem`](../../../core/PkiBase/classes/PkiBase.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toString`](../../../core/PkiBase/classes/PkiBase.md#tostring)

---

### builder()

> `static` **builder**(): [`EnvelopedDataBuilder`](../../../core/builders/EnvelopedDataBuilder/classes/EnvelopedDataBuilder.md)

#### Returns

[`EnvelopedDataBuilder`](../../../core/builders/EnvelopedDataBuilder/classes/EnvelopedDataBuilder.md)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `EnvelopedData`

Creates an EnvelopedData from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`EnvelopedData`

---

### fromCms()

> `static` **fromCms**(`cms`): `EnvelopedData`

#### Parameters

##### cms

`Uint8Array`\<`ArrayBufferLike`\> | [`ContentInfo`](../../ContentInfo/classes/ContentInfo.md)

#### Returns

`EnvelopedData`

---

### fromDer()

> `static` **fromDer**(`der`): `EnvelopedData`

#### Parameters

##### der

`Uint8Array`

#### Returns

`EnvelopedData`
