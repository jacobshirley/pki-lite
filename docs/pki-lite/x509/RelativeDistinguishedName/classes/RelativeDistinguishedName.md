[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/RelativeDistinguishedName](../README.md) / RelativeDistinguishedName

# Class: RelativeDistinguishedName

Represents a relative distinguished name (RDN).

## Asn

```asn
RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
```

## Extends

- [`PkiSet`](../../../core/PkiBase/classes/PkiSet.md)\<[`AttributeTypeAndValue`](../../AttributeTypeAndValue/classes/AttributeTypeAndValue.md)\>

## Indexable

\[`n`: `number`\]: [`AttributeTypeAndValue`](../../AttributeTypeAndValue/classes/AttributeTypeAndValue.md)

## Constructors

### Constructor

> **new RelativeDistinguishedName**(`arrayLength`): `RelativeDistinguishedName`

#### Parameters

##### arrayLength

`number`

#### Returns

`RelativeDistinguishedName`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`constructor`](../../../core/PkiBase/classes/PkiSet.md#constructor)

### Constructor

> **new RelativeDistinguishedName**(...`items`): `RelativeDistinguishedName`

#### Parameters

##### items

...[`AttributeTypeAndValue`](../../AttributeTypeAndValue/classes/AttributeTypeAndValue.md)[]

#### Returns

`RelativeDistinguishedName`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`constructor`](../../../core/PkiBase/classes/PkiSet.md#constructor)

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`maxSize`](../../../core/PkiBase/classes/PkiSet.md#maxsize)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`pemHeader`](../../../core/PkiBase/classes/PkiSet.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`pkiType`](../../../core/PkiBase/classes/PkiSet.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this set with another for equality.
Two sets are considered equal if they have the same length and
all corresponding items are equal.

#### Parameters

##### other

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md)\<[`AttributeTypeAndValue`](../../AttributeTypeAndValue/classes/AttributeTypeAndValue.md)\>

The other set to compare with

#### Returns

`boolean`

true if the sets are equal, false otherwise

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`equals`](../../../core/PkiBase/classes/PkiSet.md#equals)

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this set as a different PKI type.

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

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`parseAs`](../../../core/PkiBase/classes/PkiSet.md#parseas)

---

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...[`AttributeTypeAndValue`](../../AttributeTypeAndValue/classes/AttributeTypeAndValue.md)[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`push`](../../../core/PkiBase/classes/PkiSet.md#push)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this set to ASN.1 SET structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

An ASN.1 SET containing all items in this collection

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toAsn1`](../../../core/PkiBase/classes/PkiSet.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toDer`](../../../core/PkiBase/classes/PkiSet.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this set.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toHumanString`](../../../core/PkiBase/classes/PkiSet.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toJSON`](../../../core/PkiBase/classes/PkiSet.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toPem`](../../../core/PkiBase/classes/PkiSet.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md).[`toString`](../../../core/PkiBase/classes/PkiSet.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `RelativeDistinguishedName`

Creates a RelativeDistinguishedName from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`RelativeDistinguishedName`

A RelativeDistinguishedName

---

### parse()

> `static` **parse**(`humanString`): `RelativeDistinguishedName`

#### Parameters

##### humanString

`string`

#### Returns

`RelativeDistinguishedName`
