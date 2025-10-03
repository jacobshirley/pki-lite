[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/SignedData](../README.md) / SignedData

# Class: SignedData

Represents a CMS/PKCS#7 SignedData structure.

SignedData is used to digitally sign content. It can contain the signed content
(attached signature) or just the signature information (detached signature).
Multiple signers can sign the same content, and certificates and CRLs can be
included for signature verification.

## Asn

```asn
SignedData ::= SEQUENCE {
     version CMSVersion,
     digestAlgorithms DigestAlgorithmIdentifiers,
     encapContentInfo EncapsulatedContentInfo,
     certificates [0] IMPLICIT CertificateSet OPTIONAL,
     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
     signerInfos SignerInfos
}
CMSVersion ::= INTEGER
DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
DigestAlgorithmIdentifier ::= AlgorithmIdentifier
SignerInfos ::= SET OF SignerInfo
CertificateSet ::= SET OF Certificate
RevocationInfoChoices ::= SET OF RevocationInfoChoice
```

## Example

```typescript
// Create signed data with builder
const signedData = await SignedData.builder()
    .setContent(new Uint8Array([0x01, 0x02, 0x03, 0x04]))
    .addSigner({
        certificate: signerCert,
        privateKey: signerPrivateKey,
    })
    .addCertificate(signerCert)
    .build()

// Verify signatures
const isValid = await signedData.verify({
    data: originalData,
})
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`SignedData`\>

## Constructors

### Constructor

> **new SignedData**(`options`): `SignedData`

#### Parameters

##### options

###### certificates?

[`CertificateChoices`](../../../x509/CertificateChoices/type-aliases/CertificateChoices.md)[]

###### crls?

[`RevocationInfoChoice`](../../../revocation/RevocationInfoChoice/type-aliases/RevocationInfoChoice.md)[]

###### digestAlgorithms

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)[]

###### encapContentInfo

[`EncapsulatedContentInfo`](../../EncapsulatedContentInfo/classes/EncapsulatedContentInfo.md)

###### signerInfos

[`SignerInfo`](../../SignerInfo/classes/SignerInfo.md)[]

###### version

`number`

#### Returns

`SignedData`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### certificates?

> `optional` **certificates**: [`CertificateSet`](../../../x509/CertificateSet/classes/CertificateSet.md)

Optional set of certificates for signature verification.

---

### crls?

> `optional` **crls**: [`RevocationInfoChoices`](../../../revocation/RevocationInfoChoices/classes/RevocationInfoChoices.md)

Optional set of certificate revocation information.

---

### digestAlgorithms

> **digestAlgorithms**: `DigestAlgorithmIdentifiers`

Set of digest algorithms used by signers.

---

### encapContentInfo

> **encapContentInfo**: [`EncapsulatedContentInfo`](../../EncapsulatedContentInfo/classes/EncapsulatedContentInfo.md)

Information about the encapsulated content being signed.

---

### signerInfos

> **signerInfos**: `SignerInfos`

---

### version

> **version**: `number`

Version of the CMS structure.

---

### CertificateSet

> `static` **CertificateSet**: _typeof_ [`CertificateSet`](../../../x509/CertificateSet/classes/CertificateSet.md)

Reference to CertificateSet class.

---

### DigestAlgorithmIdentifier

> `static` **DigestAlgorithmIdentifier**: _typeof_ [`DigestAlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/DigestAlgorithmIdentifier.md)

Reference to DigestAlgorithmIdentifier class.

---

### DigestAlgorithmIdentifiers

> `static` **DigestAlgorithmIdentifiers**: _typeof_ `DigestAlgorithmIdentifiers`

Reference to DigestAlgorithmIdentifiers class.

---

### RevocationInfoChoices

> `static` **RevocationInfoChoices**: _typeof_ [`RevocationInfoChoices`](../../../revocation/RevocationInfoChoices/classes/RevocationInfoChoices.md)

Reference to RevocationInfoChoices class.

---

### SignerInfos

> `static` **SignerInfos**: _typeof_ `SignerInfos`

Reference to SignerInfos class.

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

Adds a CRL to the SignedData's CRLs.

#### Parameters

##### crl

[`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md)

The CertificateList (CRL) to add

#### Returns

`void`

---

### addOcsp()

> **addOcsp**(`OCSP`): `void`

Adds an OCSPResponse to the SignedData's CRLs.

#### Parameters

##### OCSP

[`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)

The OCSPResponse to add

#### Returns

`void`

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

Converts the SignedData to an ASN.1 structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toCms()

> **toCms**(): [`ContentInfo`](../../ContentInfo/classes/ContentInfo.md)

Returns a ContentInfo object with this SignedData as content

#### Returns

[`ContentInfo`](../../ContentInfo/classes/ContentInfo.md)

ContentInfo object

---

### toDer()

> **toDer**(): `Uint8Array<ArrayBuffer>`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array<ArrayBuffer>`

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

### verify()

> **verify**(`options`): `Promise`\<\{ `signerInfo`: [`SignerInfo`](../../SignerInfo/classes/SignerInfo.md); `valid`: `true`; \} \| \{ `reasons`: `string`[]; `valid`: `false`; \}\>

Verifies the signatures in the SignedData object.

#### Parameters

##### options

Verification options

###### certificateValidation?

`true` \| [`CertificateValidationOptions`](../../../core/CertificateValidator/interfaces/CertificateValidationOptions.md)

Certificate validation options or true for default validation

###### data?

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

Optional original data for detached signatures

#### Returns

`Promise`\<\{ `signerInfo`: [`SignerInfo`](../../SignerInfo/classes/SignerInfo.md); `valid`: `true`; \} \| \{ `reasons`: `string`[]; `valid`: `false`; \}\>

---

### builder()

> `static` **builder**(): [`SignedDataBuilder`](../../../core/builders/SignedDataBuilder/classes/SignedDataBuilder.md)

Creates a builder for constructing a SignedData object.

#### Returns

[`SignedDataBuilder`](../../../core/builders/SignedDataBuilder/classes/SignedDataBuilder.md)

A new SignedDataBuilder instance

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SignedData`

Creates a SignedData from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`SignedData`

The SignedData object

---

### fromCms()

> `static` **fromCms**(`cms`): `SignedData`

Creates a SignedData from a ContentInfo structure or DER bytes.

#### Parameters

##### cms

The ContentInfo or DER bytes

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> | [`ContentInfo`](../../ContentInfo/classes/ContentInfo.md)

#### Returns

`SignedData`

The SignedData object

---

### fromDer()

> `static` **fromDer**(`der`): `SignedData`

Creates a SignedData from a DER-encoded byte array.

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

The DER-encoded SignedData

#### Returns

`SignedData`

The SignedData object
