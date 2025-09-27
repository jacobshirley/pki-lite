[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / x400Address

# Class: x400Address

TODO: define this properly

## Extends

- [`Any`](../../../asn1/Any/classes/Any.md)

## Constructors

### Constructor

> **new x400Address**(`options`): `x400Address`

#### Parameters

##### options

###### derBytes

`null` \| `string` \| `number` \| `boolean` \| [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md) \| `ArrayBuffer` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\> \| [`Any`](../../../asn1/Any/classes/Any.md)

#### Returns

`x400Address`

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`constructor`](../../../asn1/Any/classes/Any.md#constructor)

## Properties

### derBytes

> **derBytes**: `null` \| `Uint8Array`\<`ArrayBufferLike`\>

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`derBytes`](../../../asn1/Any/classes/Any.md#derbytes)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`pemHeader`](../../../asn1/Any/classes/Any.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`pkiType`](../../../asn1/Any/classes/Any.md#pkitype)

## Methods

### asInteger()

> **asInteger**(): `number`

#### Returns

`number`

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`asInteger`](../../../asn1/Any/classes/Any.md#asinteger)

---

### asString()

> **asString**(): `string`

#### Returns

`string`

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`asString`](../../../asn1/Any/classes/Any.md#asstring)

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

[`Any`](../../../asn1/Any/classes/Any.md).[`equals`](../../../asn1/Any/classes/Any.md#equals)

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

[`Any`](../../../asn1/Any/classes/Any.md).[`parseAs`](../../../asn1/Any/classes/Any.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

The ASN.1 representation of this object

#### Overrides

[`Any`](../../../asn1/Any/classes/Any.md).[`toAsn1`](../../../asn1/Any/classes/Any.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`

The DER-encoded bytes of this object

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`toDer`](../../../asn1/Any/classes/Any.md#toder)

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

[`Any`](../../../asn1/Any/classes/Any.md).[`toHumanString`](../../../asn1/Any/classes/Any.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`toJSON`](../../../asn1/Any/classes/Any.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`toPem`](../../../asn1/Any/classes/Any.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`toString`](../../../asn1/Any/classes/Any.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `x400Address`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`x400Address`

#### Overrides

[`Any`](../../../asn1/Any/classes/Any.md).[`fromAsn1`](../../../asn1/Any/classes/Any.md#fromasn1)

---

### fromDer()

> `static` **fromDer**(`derBytes`): [`Any`](../../../asn1/Any/classes/Any.md)

#### Parameters

##### derBytes

`ArrayBuffer` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

[`Any`](../../../asn1/Any/classes/Any.md)

#### Inherited from

[`Any`](../../../asn1/Any/classes/Any.md).[`fromDer`](../../../asn1/Any/classes/Any.md#fromder)
