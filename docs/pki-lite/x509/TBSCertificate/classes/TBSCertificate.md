[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/TBSCertificate](../README.md) / TBSCertificate

# Class: TBSCertificate

Represents the "To Be Signed" part of the certificate.

## Asn

```asn
TBSCertificate  ::=  SEQUENCE  {
     version         [0]  EXPLICIT Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     extensions      [3]  EXPLICIT Extensions OPTIONAL
}

CertificateSerialNumber ::= INTEGER
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`TBSCertificate`\>

## Constructors

### Constructor

> **new TBSCertificate**(`options`): `TBSCertificate`

#### Parameters

##### options

###### extensions?

[`Extension`](../../Extension/classes/Extension.md)[]

###### issuer

[`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

###### issuerUniqueID?

`Uint8Array`\<`ArrayBuffer`\>

###### serialNumber

`string` \| `number` \| `bigint` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`Integer`](../../../asn1/Integer/classes/Integer.md)

###### signature

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### subject

[`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

###### subjectPublicKeyInfo

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

###### subjectUniqueID?

`Uint8Array`\<`ArrayBuffer`\>

###### validity

[`Validity`](../../Validity/classes/Validity.md)

###### version?

`number`

#### Returns

`TBSCertificate`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### extensions?

> `optional` **extensions**: [`Extension`](../../Extension/classes/Extension.md)[]

---

### issuer

> **issuer**: [`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

---

### issuerUniqueID?

> `optional` **issuerUniqueID**: `Uint8Array`\<`ArrayBuffer`\>

---

### serialNumber

> **serialNumber**: [`Integer`](../../../asn1/Integer/classes/Integer.md)

---

### signature

> **signature**: [`SignatureAlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/SignatureAlgorithmIdentifier.md)

---

### subject

> **subject**: [`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

---

### subjectPublicKeyInfo

> **subjectPublicKeyInfo**: [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

---

### subjectUniqueID?

> `optional` **subjectUniqueID**: `Uint8Array`\<`ArrayBuffer`\>

---

### validity

> **validity**: [`Validity`](../../Validity/classes/Validity.md)

---

### version

> **version**: `number`

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

### getExtensionByName()

> **getExtensionByName**(`name`): `undefined` \| [`Extension`](../../Extension/classes/Extension.md)

#### Parameters

##### name

`"SUBJECT_KEY_IDENTIFIER"` | `"KEY_USAGE"` | `"SUBJECT_ALT_NAME"` | `"BASIC_CONSTRAINTS"` | `"CRL_NUMBER"` | `"NAME_CONSTRAINTS"` | `"CRL_DISTRIBUTION_POINTS"` | `"CERTIFICATE_POLICIES"` | `"ANY_POLICY"` | `"POLICY_MAPPINGS"` | `"POLICY_CONSTRAINTS"` | `"INHIBIT_ANY_POLICY"` | `"AUTHORITY_KEY_IDENTIFIER"` | `"EXTENDED_KEY_USAGE"` | `"AUTHORITY_INFO_ACCESS"` | `"CRL_REASON_CODE"` | `"DELTA_CRL_INDICATOR"` | `"ISSUING_DISTRIBUTION_POINT"` | `"CERTIFICATE_ISSUER"` | `"FRESHEST_CRL"` | `"ISSUER_ALT_NAME"` | `"INVALIDITY_DATE"` | `"HOLD_INSTRUCTION_CODE"`

#### Returns

`undefined` \| [`Extension`](../../Extension/classes/Extension.md)

---

### getExtensionByOid()

> **getExtensionByOid**(`oid`): `undefined` \| [`Extension`](../../Extension/classes/Extension.md)

#### Parameters

##### oid

`string`

#### Returns

`undefined` \| [`Extension`](../../Extension/classes/Extension.md)

---

### getExtensionsByName()

> **getExtensionsByName**(`name`): [`Extension`](../../Extension/classes/Extension.md)[]

#### Parameters

##### name

`"SUBJECT_KEY_IDENTIFIER"` | `"KEY_USAGE"` | `"SUBJECT_ALT_NAME"` | `"BASIC_CONSTRAINTS"` | `"CRL_NUMBER"` | `"NAME_CONSTRAINTS"` | `"CRL_DISTRIBUTION_POINTS"` | `"CERTIFICATE_POLICIES"` | `"ANY_POLICY"` | `"POLICY_MAPPINGS"` | `"POLICY_CONSTRAINTS"` | `"INHIBIT_ANY_POLICY"` | `"AUTHORITY_KEY_IDENTIFIER"` | `"EXTENDED_KEY_USAGE"` | `"AUTHORITY_INFO_ACCESS"` | `"CRL_REASON_CODE"` | `"DELTA_CRL_INDICATOR"` | `"ISSUING_DISTRIBUTION_POINT"` | `"CERTIFICATE_ISSUER"` | `"FRESHEST_CRL"` | `"ISSUER_ALT_NAME"` | `"INVALIDITY_DATE"` | `"HOLD_INSTRUCTION_CODE"`

#### Returns

[`Extension`](../../Extension/classes/Extension.md)[]

---

### getExtensionsByOid()

> **getExtensionsByOid**(`oid`): [`Extension`](../../Extension/classes/Extension.md)[]

#### Parameters

##### oid

`string`

#### Returns

[`Extension`](../../Extension/classes/Extension.md)[]

---

### getIssuerSerial()

> **getIssuerSerial**(): [`IssuerSerial`](../../IssuerSerial/classes/IssuerSerial.md)

#### Returns

[`IssuerSerial`](../../IssuerSerial/classes/IssuerSerial.md)

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

Converts the TBSCertificate to an ASN.1 structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

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

### toOriginalDer()

> **toOriginalDer**(): `Uint8Array`\<`ArrayBuffer`\>

The DER this object was parsed from, if it has not been changed since; otherwise
[toDer](../../../core/PkiBase/classes/PkiBase.md#toder). Use it for the bytes a signature covers (a certificate's or CRL's
TBS part): re-encoding a parsed value does not always give back the same bytes (a
GeneralizedTime before 2050 becomes a UTCTime, a string changes type, ...), and any
difference breaks the signature. Only types that keep their encoding when parsed
(TBSCertificate, TBSCertList, CertificateRequestInfo) have one to return.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The original encoding, or the current one

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toOriginalDer`](../../../core/PkiBase/classes/PkiBase.md#tooriginalder)

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

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `TBSCertificate`

Creates a TBSCertificate from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`TBSCertificate`

The TBSCertificate
