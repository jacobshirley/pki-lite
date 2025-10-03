[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / PkiArray

# Abstract Class: PkiArray\<T\>

Base class for arrays of PKI objects.

Extends the native Array class with PKI-specific functionality including
size limits, PEM encoding, and ASN.1 serialization capabilities.

## Extends

- `Array`\<`T`\>

## Extended by

- [`PkiSet`](PkiSet.md)
- [`PkiSequence`](PkiSequence.md)

## Type Parameters

### T

`T` _extends_ [`PkiBase`](PkiBase.md)\<`any`\>

The type of PKI objects contained in this array

## Indexable

\[`n`: `number`\]: `T`

## Constructors

### Constructor

> **new PkiArray**\<`T`\>(`arrayLength`): `PkiArray`\<`T`\>

#### Parameters

##### arrayLength

`number`

#### Returns

`PkiArray`\<`T`\>

#### Inherited from

`Array<T>.constructor`

### Constructor

> **new PkiArray**\<`T`\>(...`items`): `PkiArray`\<`T`\>

#### Parameters

##### items

...`T`[]

#### Returns

`PkiArray`\<`T`\>

#### Inherited from

`Array<T>.constructor`

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

## Methods

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...`T`[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Overrides

`Array.push`

---

### toAsn1()

> `abstract` **toAsn1**(): [`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

Converts this array to its ASN.1 representation.
Must be implemented by subclasses to specify SET or SEQUENCE.

#### Returns

[`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

The ASN.1 representation of this array

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

---

### toJSON()

> **toJSON**(): [`ToJson`](../type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Overrides

`Array.toString`
