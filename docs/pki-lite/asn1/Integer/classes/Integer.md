[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [asn1/Integer](../README.md) / Integer

# Class: Integer

Represents an ASN.1 INTEGER value.
Handles both small and large integers with full support for
multi-byte values including those exceeding JavaScript's Number limits.

## Asn

```asn
Integer ::= <value>
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`Integer`\>

## Constructors

### Constructor

> **new Integer**(`options`): `Integer`

Creates a new Integer instance

#### Parameters

##### options

###### value

`string` \| `number` \| `bigint` \| `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| `Integer`

#### Returns

`Integer`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### bytes

> **bytes**: `Uint8Array<ArrayBuffer>`

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`pemHeader`](../../../core/PkiBase/classes/PkiBase.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`pkiType`](../../../core/PkiBase/classes/PkiBase.md#pkitype)

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

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`equals`](../../../core/PkiBase/classes/PkiBase.md#equals)

---

### get()

> **get**(): `number`

Gets the integer value.

#### Returns

`number`

The JavaScript number representation of the integer

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

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`parseAs`](../../../core/PkiBase/classes/PkiBase.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Integer`](../../../core/PkiBase/namespaces/asn1js/classes/Integer.md)

Converts the Integer to an ASN.1 INTEGER structure

#### Returns

[`Integer`](../../../core/PkiBase/namespaces/asn1js/classes/Integer.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toBigInt()

> **toBigInt**(): `bigint`

Converts to a BigInt value, which can handle integers of arbitrary precision

#### Returns

`bigint`

---

### toDer()

> **toDer**(): `Uint8Array<ArrayBuffer>`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array<ArrayBuffer>`

The DER-encoded bytes of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toDer`](../../../core/PkiBase/classes/PkiBase.md#toder)

---

### toHexString()

> **toHexString**(): `string`

Converts the Integer to a hexadecimal string
This method is primarily for display purposes and removes any leading zeros
added for ASN.1 encoding compliance

#### Returns

`string`

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

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toHumanString`](../../../core/PkiBase/classes/PkiBase.md#tohumanstring)

---

### toInteger()

> **toInteger**(): `number`

Converts to a JavaScript number.
Warning: Will lose precision for integers larger than Number.MAX_SAFE_INTEGER

#### Returns

`number`

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toJSON`](../../../core/PkiBase/classes/PkiBase.md#tojson)

---

### toNumber()

> **toNumber**(): `number`

Alias of `toInteger()`

#### Returns

`number`

The JavaScript number representation of the integer

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toPem`](../../../core/PkiBase/classes/PkiBase.md#topem)

---

### toString()

> **toString**(): `string`

Returns string representation of the integer

#### Returns

`string`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toString`](../../../core/PkiBase/classes/PkiBase.md#tostring)

---

### toUnsigned()

> **toUnsigned**(): `Uint8Array<ArrayBuffer>`

#### Returns

`Uint8Array<ArrayBuffer>`

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `Integer`

Creates an Integer from an ASN.1 INTEGER structure

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`Integer`
