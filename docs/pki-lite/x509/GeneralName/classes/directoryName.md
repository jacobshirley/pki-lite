[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / directoryName

# Class: directoryName

## Extends

- `RDNSequence`

## Indexable

\[`n`: `number`\]: [`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)

## Constructors

### Constructor

> **new directoryName**(`arrayLength`): `directoryName`

#### Parameters

##### arrayLength

`number`

#### Returns

`directoryName`

#### Inherited from

`Name.RDNSequence.constructor`

### Constructor

> **new directoryName**(...`items`): `directoryName`

#### Parameters

##### items

...[`RelativeDistinguishedName`](../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)[]

#### Returns

`directoryName`

#### Inherited from

`Name.RDNSequence.constructor`

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

`Name.RDNSequence.maxSize`

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

`Name.RDNSequence.pemHeader`

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

`Name.RDNSequence.pkiType`

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

`Name.RDNSequence.equals`

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

`Name.RDNSequence.parseAs`

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

`Name.RDNSequence.push`

---

### toAsn1()

> **toAsn1**(): `Sequence`

Converts this sequence to ASN.1 SEQUENCE structure.

#### Returns

`Sequence`

An ASN.1 SEQUENCE containing all items in order

#### Overrides

`Name.RDNSequence.toAsn1`

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

#### Inherited from

`Name.RDNSequence.toDer`

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this sequence.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Inherited from

`Name.RDNSequence.toHumanString`

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

#### Inherited from

`Name.RDNSequence.toJSON`

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

`Name.RDNSequence.toPem`

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

`Name.RDNSequence.toString`

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `directoryName`

Creates an RDNSequence from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`directoryName`

An RDNSequence

#### Overrides

`Name.RDNSequence.fromAsn1`

---

### fromName()

> `static` **fromName**(`rdnSequence`): `directoryName`

#### Parameters

##### rdnSequence

[`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

#### Returns

`directoryName`

---

### parse()

> `static` **parse**(`humanString`): [`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

#### Parameters

##### humanString

`string` | [`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

#### Returns

[`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

#### Inherited from

`Name.RDNSequence.parse`
