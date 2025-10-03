[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [x509/attribute-certs/AttributeCertificateInfo](../README.md) / AttributeCertificateInfo

# Class: AttributeCertificateInfo

Represents the information in an attribute certificate.
According to RFC 5755, the attribute certificate info is defined as:

## Asn

```asn
AttributeCertificateInfo ::= SEQUENCE {
    version              AttCertVersion -- version is v2,
    holder               Holder,
    issuer               AttCertIssuer,
    signature            AlgorithmIdentifier,
    serialNumber         CertificateSerialNumber,
    attrCertValidityPeriod   AttCertValidityPeriod,
    attributes           SEQUENCE OF Attribute,
    issuerUniqueID       UniqueIdentifier OPTIONAL,
    extensions           Extensions OPTIONAL
}

AttCertVersion ::= INTEGER { v2(1) }

AttCertValidityPeriod ::= SEQUENCE {
    notBeforeTime  GeneralizedTime,
    notAfterTime   GeneralizedTime
}
```

## Extends

- [`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md)\<`AttributeCertificateInfo`\>

## Constructors

### Constructor

> **new AttributeCertificateInfo**(`options`): `AttributeCertificateInfo`

Creates a new AttributeCertificateInfo instance.

#### Parameters

##### options

###### attributes

[`Attribute`](../../../Attribute/classes/Attribute.md)[]

###### extensions?

[`Extension`](../../../Extension/classes/Extension.md)[]

###### holder

[`Holder`](Holder.md)

###### issuer

[`AttCertIssuer`](AttCertIssuer.md)

###### issuerUniqueID?

`Uint8Array`\<`ArrayBuffer`\>

###### serialNumber

`Uint8Array`\<`ArrayBuffer`\>

###### signature

[`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### validityPeriod

\{ `notAfter`: `Date`; `notBefore`: `Date`; \}

###### validityPeriod.notAfter

`Date`

###### validityPeriod.notBefore

`Date`

###### version

`number`

#### Returns

`AttributeCertificateInfo`

#### Overrides

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### attributes

> **attributes**: [`Attribute`](../../../Attribute/classes/Attribute.md)[]

---

### extensions?

> `optional` **extensions**: [`Extension`](../../../Extension/classes/Extension.md)[]

---

### holder

> **holder**: [`Holder`](Holder.md)

---

### issuer

> **issuer**: [`AttCertIssuer`](AttCertIssuer.md)

---

### issuerUniqueID?

> `optional` **issuerUniqueID**: `Uint8Array`\<`ArrayBuffer`\>

---

### serialNumber

> **serialNumber**: `Uint8Array`\<`ArrayBuffer`\>

---

### signature

> **signature**: [`AlgorithmIdentifier`](../../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

---

### validityPeriod

> **validityPeriod**: `object`

#### notAfter

> **notAfter**: `Date`

#### notBefore

> **notBefore**: `Date`

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

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`pemHeader`](../../../../core/PkiBase/classes/PkiBase.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`pkiType`](../../../../core/PkiBase/classes/PkiBase.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this PKI object with another for equality.
Two objects are considered equal if their DER encodings are identical.

#### Parameters

##### other

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md)\<`any`\>

The other PKI object to compare with

#### Returns

`boolean`

true if the objects are equal, false otherwise

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`equals`](../../../../core/PkiBase/classes/PkiBase.md#equals)

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

[`ParseableAsn1`](../../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`parseAs`](../../../../core/PkiBase/classes/PkiBase.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts the AttributeCertificateInfo to an ASN.1 structure.

#### Returns

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`toDer`](../../../../core/PkiBase/classes/PkiBase.md#toder)

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

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`toHumanString`](../../../../core/PkiBase/classes/PkiBase.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`toJSON`](../../../../core/PkiBase/classes/PkiBase.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`toPem`](../../../../core/PkiBase/classes/PkiBase.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiBase`](../../../../core/PkiBase/classes/PkiBase.md).[`toString`](../../../../core/PkiBase/classes/PkiBase.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `AttributeCertificateInfo`

Creates an AttributeCertificateInfo from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`AttributeCertificateInfo`

The AttributeCertificateInfo
