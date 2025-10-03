[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [x509/extensions/SubjectAltName](../README.md) / SubjectAltName

# Class: SubjectAltName

Represents a SEQUENCE OF PKI objects in ASN.1.

A SEQUENCE contains an ordered collection of objects, which may be of
different types. This class provides SEQUENCE-specific ASN.1 encoding
and comparison methods.

## Extends

- [`GeneralNames`](../../../GeneralName/classes/GeneralNames.md)

## Indexable

\[`n`: `number`\]: [`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)

## Constructors

### Constructor

> **new SubjectAltName**(`arrayLength`): `SubjectAltName`

#### Parameters

##### arrayLength

`number`

#### Returns

`SubjectAltName`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`constructor`](../../../GeneralName/classes/GeneralNames.md#constructor)

### Constructor

> **new SubjectAltName**(...`items`): `SubjectAltName`

#### Parameters

##### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

#### Returns

`SubjectAltName`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`constructor`](../../../GeneralName/classes/GeneralNames.md#constructor)

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`maxSize`](../../../GeneralName/classes/GeneralNames.md#maxsize)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`pemHeader`](../../../GeneralName/classes/GeneralNames.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`pkiType`](../../../GeneralName/classes/GeneralNames.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this sequence with another for equality.
Two sequences are considered equal if they have the same length and
all corresponding items are equal in the same order.

#### Parameters

##### other

[`PkiSequence`](../../../../core/PkiBase/classes/PkiSequence.md)\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

The other sequence to compare with

#### Returns

`boolean`

true if the sequences are equal, false otherwise

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`equals`](../../../GeneralName/classes/GeneralNames.md#equals)

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

[`ParseableAsn1`](../../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`parseAs`](../../../GeneralName/classes/GeneralNames.md#parseas)

---

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`push`](../../../GeneralName/classes/GeneralNames.md#push)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this sequence to ASN.1 SEQUENCE structure.

#### Returns

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

An ASN.1 SEQUENCE containing all items in order

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toAsn1`](../../../GeneralName/classes/GeneralNames.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toDer`](../../../GeneralName/classes/GeneralNames.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this sequence.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toHumanString`](../../../GeneralName/classes/GeneralNames.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../../core/PkiBase/type-aliases/ToJson.md)\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../../core/PkiBase/type-aliases/ToJson.md)\<[`GeneralName`](../../../GeneralName/type-aliases/GeneralName.md)\>

A JSON-serializable representation of this array

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toJSON`](../../../GeneralName/classes/GeneralNames.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toPem`](../../../GeneralName/classes/GeneralNames.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`toString`](../../../GeneralName/classes/GeneralNames.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SubjectAltName`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`SubjectAltName`

#### Overrides

[`GeneralNames`](../../../GeneralName/classes/GeneralNames.md).[`fromAsn1`](../../../GeneralName/classes/GeneralNames.md#fromasn1)
