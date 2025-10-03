[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/SignerInfo](../README.md) / SignedAttributes

# Class: SignedAttributes

Represents a set of signed attributes.

This class is used to group together attributes that are signed.

## Asn

```asn
SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
```

## Extends

- [`Attributes`](../../../x509/Attributes/classes/Attributes.md)

## Indexable

\[`n`: `number`\]: [`Attribute`](../../../x509/Attribute/classes/Attribute.md)

## Constructors

### Constructor

> **new SignedAttributes**(`arrayLength`): `SignedAttributes`

#### Parameters

##### arrayLength

`number`

#### Returns

`SignedAttributes`

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`constructor`](../../../x509/Attributes/classes/Attributes.md#constructor)

### Constructor

> **new SignedAttributes**(...`items`): `SignedAttributes`

#### Parameters

##### items

...[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

#### Returns

`SignedAttributes`

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`constructor`](../../../x509/Attributes/classes/Attributes.md#constructor)

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`maxSize`](../../../x509/Attributes/classes/Attributes.md#maxsize)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`pemHeader`](../../../x509/Attributes/classes/Attributes.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`pkiType`](../../../x509/Attributes/classes/Attributes.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this set with another for equality.
Two sets are considered equal if they have the same length and
all corresponding items are equal.

#### Parameters

##### other

[`PkiSet`](../../../core/PkiBase/classes/PkiSet.md)\<[`Attribute`](../../../x509/Attribute/classes/Attribute.md)\>

The other set to compare with

#### Returns

`boolean`

true if the sets are equal, false otherwise

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`equals`](../../../x509/Attributes/classes/Attributes.md#equals)

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

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`parseAs`](../../../x509/Attributes/classes/Attributes.md#parseas)

---

### push()

> **push**(...`items`): `number`

Adds new PKI objects to the end of the array.
Respects the maxSize limit if set.

#### Parameters

##### items

...[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

The PKI objects to add

#### Returns

`number`

The new length of the array

#### Throws

Error if adding items would exceed maxSize

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`push`](../../../x509/Attributes/classes/Attributes.md#push)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this set to ASN.1 SET structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

An ASN.1 SET containing all items in this collection

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`toAsn1`](../../../x509/Attributes/classes/Attributes.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`toDer`](../../../x509/Attributes/classes/Attributes.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this set.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`toHumanString`](../../../x509/Attributes/classes/Attributes.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`toJSON`](../../../x509/Attributes/classes/Attributes.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`toPem`](../../../x509/Attributes/classes/Attributes.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`toString`](../../../x509/Attributes/classes/Attributes.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SignedAttributes`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`SignedAttributes`

#### Overrides

[`Attributes`](../../../x509/Attributes/classes/Attributes.md).[`fromAsn1`](../../../x509/Attributes/classes/Attributes.md#fromasn1)
