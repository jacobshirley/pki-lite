[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / otherName

# Class: otherName

## Extends

- [`AnotherName`](AnotherName.md)

## Constructors

### Constructor

> **new otherName**(`options`): `otherName`

#### Parameters

##### options

###### typeID

`string` \| [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

###### value

[`Asn1Any`](../../../core/PkiBase/type-aliases/Asn1Any.md)

#### Returns

`otherName`

#### Inherited from

[`AnotherName`](AnotherName.md).[`constructor`](AnotherName.md#constructor)

## Properties

### typeID

> **typeID**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Inherited from

[`AnotherName`](AnotherName.md).[`typeID`](AnotherName.md#typeid)

---

### value

> **value**: [`Any`](../../../asn1/Any/classes/Any.md)

#### Inherited from

[`AnotherName`](AnotherName.md).[`value`](AnotherName.md#value)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`AnotherName`](AnotherName.md).[`pemHeader`](AnotherName.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`AnotherName`](AnotherName.md).[`pkiType`](AnotherName.md#pkitype)

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

[`AnotherName`](AnotherName.md).[`equals`](AnotherName.md#equals)

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

[`AnotherName`](AnotherName.md).[`parseAs`](AnotherName.md#parseas)

---

### toAsn1()

> **toAsn1**(): `Sequence`

[0] IMPLICIT AnotherName: the SEQUENCE's children sit directly in [0]

#### Returns

`Sequence`

#### Overrides

[`AnotherName`](AnotherName.md).[`toAsn1`](AnotherName.md#toasn1)

---

### toAsn1Children()

> `protected` **toAsn1Children**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)[]

The children of the structure: `type-id OBJECT IDENTIFIER` followed by
`value [0] EXPLICIT ANY`.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)[]

#### Inherited from

[`AnotherName`](AnotherName.md).[`toAsn1Children`](AnotherName.md#toasn1children)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`AnotherName`](AnotherName.md).[`toDer`](AnotherName.md#toder)

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

[`AnotherName`](AnotherName.md).[`toHumanString`](AnotherName.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`AnotherName`](AnotherName.md).[`toJSON`](AnotherName.md#tojson)

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

[`AnotherName`](AnotherName.md).[`toOriginalDer`](AnotherName.md#tooriginalder)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`AnotherName`](AnotherName.md).[`toPem`](AnotherName.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`AnotherName`](AnotherName.md).[`toString`](AnotherName.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `otherName`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

A SEQUENCE (or an element whose children are the same two
fields, as is the case for the implicitly tagged otherName)

#### Returns

`otherName`

#### Overrides

[`AnotherName`](AnotherName.md).[`fromAsn1`](AnotherName.md#fromasn1)
