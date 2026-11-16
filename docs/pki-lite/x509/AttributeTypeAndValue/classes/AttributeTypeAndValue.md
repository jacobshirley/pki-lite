[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/AttributeTypeAndValue](../README.md) / AttributeTypeAndValue

# Class: AttributeTypeAndValue

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`AttributeTypeAndValue`\>

## Constructors

### Constructor

> **new AttributeTypeAndValue**(`options`): `AttributeTypeAndValue`

#### Parameters

##### options

###### type

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

###### value

[`Asn1Any`](../../../core/PkiBase/type-aliases/Asn1Any.md)

#### Returns

`AttributeTypeAndValue`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### type

> **type**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

---

### value

> **value**: [`Any`](../../../asn1/Any/classes/Any.md)

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

---

### shortName

#### Get Signature

> **get** **shortName**(): `string`

##### Returns

`string`

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

### matches()

> **matches**(`other`): `boolean`

Whether this attribute matches another as RFC 5280 7.1 compares names: the same
type, and values equal after RFC 4518 string preparation. A character string, in
whatever ASN.1 string type, is Unicode-normalised (NFKC), case-folded and has
leading, trailing and repeated whitespace removed, so PrintableString "Test CA"
matches UTF8String "test ca". Other values must have the same DER encoding.

#### Parameters

##### other

`AttributeTypeAndValue`

#### Returns

`boolean`

#### Example

```typescript
AttributeTypeAndValue.parse('CN=Test  CA').matches(
    AttributeTypeAndValue.parse('cn=test ca'),
) // true
```

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

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 representation of this object

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

#### Overrides

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

> `static` **fromAsn1**(`asn1`): `AttributeTypeAndValue`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`AttributeTypeAndValue`

---

### parse()

> `static` **parse**(`humanString`): `AttributeTypeAndValue`

#### Parameters

##### humanString

`string`

#### Returns

`AttributeTypeAndValue`
