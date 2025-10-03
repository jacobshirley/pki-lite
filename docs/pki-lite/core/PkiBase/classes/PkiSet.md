[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / PkiSet

# Class: PkiSet\<T\>

Represents a SET OF PKI objects in ASN.1.

A SET contains an unordered collection of objects of the same type.
This class provides SET-specific ASN.1 encoding and comparison methods.

## Extends

- [`PkiArray`](PkiArray.md)\<`T`\>

## Extended by

- [`RevocationInfoChoices`](../../../revocation/RevocationInfoChoices/classes/RevocationInfoChoices.md)
- [`Attributes`](../../../x509/Attributes/classes/Attributes.md)
- [`CertificateSet`](../../../x509/CertificateSet/classes/CertificateSet.md)
- [`RelativeDistinguishedName`](../../../x509/RelativeDistinguishedName/classes/RelativeDistinguishedName.md)
- [`RecipientEncryptedKeys`](../../../pkcs7/recipients/KeyAgreeRecipientInfo/classes/RecipientEncryptedKeys.md)

## Type Parameters

### T

`T` _extends_ [`PkiBase`](PkiBase.md)\<`any`\> = `any`

The type of PKI objects contained in this set

## Indexable

\[`n`: `number`\]: `T`

## Constructors

### Constructor

> **new PkiSet**\<`T`\>(`arrayLength`): `PkiSet`\<`T`\>

#### Parameters

##### arrayLength

`number`

#### Returns

`PkiSet`\<`T`\>

#### Inherited from

[`PkiArray`](PkiArray.md).[`constructor`](PkiArray.md#constructor)

### Constructor

> **new PkiSet**\<`T`\>(...`items`): `PkiSet`\<`T`\>

#### Parameters

##### items

...`T`[]

#### Returns

`PkiSet`\<`T`\>

#### Inherited from

[`PkiArray`](PkiArray.md).[`constructor`](PkiArray.md#constructor)

## Properties

### maxSize?

> `protected` `optional` **maxSize**: `number`

#### Inherited from

[`PkiArray`](PkiArray.md).[`maxSize`](PkiArray.md#maxsize)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this array type.

##### Returns

`string`

#### Inherited from

[`PkiArray`](PkiArray.md).[`pemHeader`](PkiArray.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this array.

##### Returns

`string`

#### Inherited from

[`PkiArray`](PkiArray.md).[`pkiType`](PkiArray.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this set with another for equality.
Two sets are considered equal if they have the same length and
all corresponding items are equal.

#### Parameters

##### other

`PkiSet`\<`T`\>

The other set to compare with

#### Returns

`boolean`

true if the sets are equal, false otherwise

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

[`ParseableAsn1`](../type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

---

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

#### Inherited from

[`PkiArray`](PkiArray.md).[`push`](PkiArray.md#push)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

Converts this set to ASN.1 SET structure.

#### Returns

[`Asn1BaseBlock`](../type-aliases/Asn1BaseBlock.md)

An ASN.1 SET containing all items in this collection

#### Overrides

[`PkiArray`](PkiArray.md).[`toAsn1`](PkiArray.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this array to DER format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this array

#### Inherited from

[`PkiArray`](PkiArray.md).[`toDer`](PkiArray.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this set.
Joins all child elements with commas.

#### Returns

`string`

A comma-separated string of child elements

---

### toJSON()

> **toJSON**(): [`ToJson`](../type-aliases/ToJson.md)\<`T`\>

Converts this array to a JSON representation.

#### Returns

[`ToJson`](../type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this array

#### Inherited from

[`PkiArray`](PkiArray.md).[`toJSON`](PkiArray.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this array to PEM format.

#### Returns

`string`

A PEM-encoded string

#### Inherited from

[`PkiArray`](PkiArray.md).[`toPem`](PkiArray.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI array.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiArray`](PkiArray.md).[`toString`](PkiArray.md#tostring)
