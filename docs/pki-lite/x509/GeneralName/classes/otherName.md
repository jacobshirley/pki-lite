[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / otherName

# Class: otherName

Base class for all PKI objects in the library.

Provides common functionality for ASN.1 encoding/decoding, PEM formatting,
DER serialization, and object comparison. All PKI structures extend this class
to ensure consistent behavior across the library.

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

> **toAsn1**(): [`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

The ASN.1 representation of this object

#### Overrides

[`AnotherName`](AnotherName.md).[`toAsn1`](AnotherName.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`

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

> `static` **fromAsn1**(`asn1`): [`AnotherName`](AnotherName.md)

#### Parameters

##### asn1

[`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

#### Returns

[`AnotherName`](AnotherName.md)

#### Inherited from

[`AnotherName`](AnotherName.md).[`fromAsn1`](AnotherName.md#fromasn1)
