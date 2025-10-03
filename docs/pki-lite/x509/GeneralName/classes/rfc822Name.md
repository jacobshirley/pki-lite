[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / rfc822Name

# Class: rfc822Name

Represents an ASN.1 IA5String (Internationalized ASCII String) value.

## Asn

```asn
IA5String ::= <value>
```

## Extends

- [`IA5String`](../../../asn1/IA5String/classes/IA5String.md)

## Constructors

### Constructor

> **new rfc822Name**(`options`): `rfc822Name`

#### Parameters

##### options

###### value

`string` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`IA5String`](../../../asn1/IA5String/classes/IA5String.md)

#### Returns

`rfc822Name`

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`constructor`](../../../asn1/IA5String/classes/IA5String.md#constructor)

## Properties

### bytes

> **bytes**: `Uint8Array`\<`ArrayBuffer`\>

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`bytes`](../../../asn1/IA5String/classes/IA5String.md#bytes)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`pemHeader`](../../../asn1/IA5String/classes/IA5String.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`pkiType`](../../../asn1/IA5String/classes/IA5String.md#pkitype)

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

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`equals`](../../../asn1/IA5String/classes/IA5String.md#equals)

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

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`parseAs`](../../../asn1/IA5String/classes/IA5String.md#parseas)

---

### toAsn1()

> **toAsn1**(): `Sequence`

Converts this PKI object to its ASN.1 representation.

#### Returns

`Sequence`

The ASN.1 representation of this object

#### Overrides

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toAsn1`](../../../asn1/IA5String/classes/IA5String.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toDer`](../../../asn1/IA5String/classes/IA5String.md#toder)

---

### toHexString()

> **toHexString**(): `string`

Converts the IA5String to a hexadecimal string

#### Returns

`string`

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toHexString`](../../../asn1/IA5String/classes/IA5String.md#tohexstring)

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

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toHumanString`](../../../asn1/IA5String/classes/IA5String.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toJSON`](../../../asn1/IA5String/classes/IA5String.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toPem`](../../../asn1/IA5String/classes/IA5String.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`toString`](../../../asn1/IA5String/classes/IA5String.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `rfc822Name`

Creates a IA5String from an ASN.1 IA5String structure

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`rfc822Name`

#### Overrides

[`IA5String`](../../../asn1/IA5String/classes/IA5String.md).[`fromAsn1`](../../../asn1/IA5String/classes/IA5String.md#fromasn1)
