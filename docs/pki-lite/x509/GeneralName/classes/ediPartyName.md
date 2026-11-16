[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / ediPartyName

# Class: ediPartyName

## Extends

- [`EDIPartyName`](EDIPartyName-1.md)

## Constructors

### Constructor

> **new ediPartyName**(`options`): `ediPartyName`

#### Parameters

##### options

###### nameAssigner?

`string` \| [`DirectoryString`](../../DirectoryString/type-aliases/DirectoryString.md)

###### partyName

`string` \| [`DirectoryString`](../../DirectoryString/type-aliases/DirectoryString.md)

#### Returns

`ediPartyName`

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`constructor`](EDIPartyName-1.md#constructor)

## Properties

### nameAssigner?

> `optional` **nameAssigner**: [`DirectoryString`](../../DirectoryString/type-aliases/DirectoryString.md)

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`nameAssigner`](EDIPartyName-1.md#nameassigner)

---

### partyName

> **partyName**: [`DirectoryString`](../../DirectoryString/type-aliases/DirectoryString.md)

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`partyName`](EDIPartyName-1.md#partyname)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`pemHeader`](EDIPartyName-1.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`pkiType`](EDIPartyName-1.md#pkitype)

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

[`EDIPartyName`](EDIPartyName-1.md).[`equals`](EDIPartyName-1.md#equals)

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

[`EDIPartyName`](EDIPartyName-1.md).[`parseAs`](EDIPartyName-1.md#parseas)

---

### toAsn1()

> **toAsn1**(): `Sequence`

[5] IMPLICIT EDIPartyName

#### Returns

`Sequence`

#### Overrides

[`EDIPartyName`](EDIPartyName-1.md).[`toAsn1`](EDIPartyName-1.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`toDer`](EDIPartyName-1.md#toder)

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

[`EDIPartyName`](EDIPartyName-1.md).[`toHumanString`](EDIPartyName-1.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`toJSON`](EDIPartyName-1.md#tojson)

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

[`EDIPartyName`](EDIPartyName-1.md).[`toOriginalDer`](EDIPartyName-1.md#tooriginalder)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`toPem`](EDIPartyName-1.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`EDIPartyName`](EDIPartyName-1.md).[`toString`](EDIPartyName-1.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `ediPartyName`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

A SEQUENCE (or an element whose children are the same fields,
as is the case for the implicitly tagged ediPartyName)

#### Returns

`ediPartyName`

#### Overrides

[`EDIPartyName`](EDIPartyName-1.md).[`fromAsn1`](EDIPartyName-1.md#fromasn1)
