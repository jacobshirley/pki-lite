[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/RDNSequence](../README.md) / RDNSequence

# Class: RDNSequence

Represents a sequence of relative distinguished names (RDNs).

## Asn

```asn
RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
```

## Extends

- [`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md)\<[`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)\>

## Indexable

\[`n`: `number`\]: [`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)

## Constructors

### Constructor

> **new RDNSequence**(`arrayLength`): `RDNSequence`

#### Parameters

##### arrayLength

`number`

#### Returns

`RDNSequence`

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`constructor`](../../../core/PkiBase/classes/PkiSequence.md#constructor)

### Constructor

> **new RDNSequence**(...`items`): `RDNSequence`

#### Parameters

##### items

...[`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)[]

#### Returns

`RDNSequence`

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`constructor`](../../../core/PkiBase/classes/PkiSequence.md#constructor)

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`maxSize`](../../../core/PkiBase/classes/PkiSequence.md#maxsize)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`pemHeader`](../../../core/PkiBase/classes/PkiSequence.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`pkiType`](../../../core/PkiBase/classes/PkiSequence.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this sequence with another for equality.
Two sequences are considered equal if they have the same length and
all corresponding items are equal in the same order.

#### Parameters

##### other

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md)\<[`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)\>

The other sequence to compare with

#### Returns

`boolean`

true if the sequences are equal, false otherwise

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`equals`](../../../core/PkiBase/classes/PkiSequence.md#equals)

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this sequence as a different PKI type.

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

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`parseAs`](../../../core/PkiBase/classes/PkiSequence.md#parseas)

---

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...[`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`push`](../../../core/PkiBase/classes/PkiSequence.md#push)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this sequence to ASN.1 SEQUENCE structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

An ASN.1 SEQUENCE containing all items in order

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`toAsn1`](../../../core/PkiBase/classes/PkiSequence.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`toDer`](../../../core/PkiBase/classes/PkiSequence.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this sequence.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Overrides

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`toHumanString`](../../../core/PkiBase/classes/PkiSequence.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`toJSON`](../../../core/PkiBase/classes/PkiSequence.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`toPem`](../../../core/PkiBase/classes/PkiSequence.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md).[`toString`](../../../core/PkiBase/classes/PkiSequence.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `RDNSequence`

Creates an RDNSequence from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`RDNSequence`

An RDNSequence

---

### parse()

> `static` **parse**(`humanString`): `RDNSequence`

#### Parameters

##### humanString

`string` | `RDNSequence`

#### Returns

`RDNSequence`
