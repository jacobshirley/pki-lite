[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [keys/ECPublicKey](../README.md) / ECPublicKey

# Class: ECPublicKey

Represents an EC key. The structure follows X9.62 format.

ASN.1 Structure:

```
ECPublicKey ::= BIT STRING
```

Note: ECPublicKey is typically used within a SubjectPublicKeyInfo structure
where it appears as the BIT STRING component of the key.
The actual encoding is the uncompressed point format:
0x04 || x || y
where 0x04 indicates uncompressed format, followed by the x and y coordinates.

## Extends

- [`BitString`](../../../asn1/BitString/classes/BitString.md)

## Constructors

### Constructor

> **new ECPublicKey**(`options`): `ECPublicKey`

Creates a new ECPublicKey

#### Parameters

##### options

###### value

`Uint8Array<ArrayBuffer>`

The key as a Uint8Array<ArrayBuffer> in uncompressed format (0x04 || x || y)

#### Returns

`ECPublicKey`

#### Overrides

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`constructor`](../../../asn1/BitString/classes/BitString.md#constructor)

## Properties

### bytes

> **bytes**: `Uint8Array<ArrayBuffer>`

The bytes representing this bit string.

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`bytes`](../../../asn1/BitString/classes/BitString.md#bytes)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`pemHeader`](../../../asn1/BitString/classes/BitString.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`pkiType`](../../../asn1/BitString/classes/BitString.md#pkitype)

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

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`equals`](../../../asn1/BitString/classes/BitString.md#equals)

---

### getCoordinates()

> **getCoordinates**(): `object`

Extracts the X and Y coordinates from the key

#### Returns

`object`

An object containing the X and Y coordinates

##### x

> **x**: `Uint8Array<ArrayBuffer>`

##### y

> **y**: `Uint8Array<ArrayBuffer>`

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

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`parseAs`](../../../asn1/BitString/classes/BitString.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this BitString to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 BIT STRING structure

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toAsn1`](../../../asn1/BitString/classes/BitString.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array<ArrayBuffer>`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array<ArrayBuffer>`

The DER-encoded bytes of this object

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toDer`](../../../asn1/BitString/classes/BitString.md#toder)

---

### toHexString()

> **toHexString**(): `string`

Converts the BitString to a hexadecimal string representation.
Each byte is represented as two lowercase hex digits.

#### Returns

`string`

The hexadecimal string (e.g., "0420abcd")

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toHexString`](../../../asn1/BitString/classes/BitString.md#tohexstring)

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

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toHumanString`](../../../asn1/BitString/classes/BitString.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toJSON`](../../../asn1/BitString/classes/BitString.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toPem`](../../../asn1/BitString/classes/BitString.md#topem)

---

### toRaw()

> **toRaw**(): `Uint8Array<ArrayBuffer>`

#### Returns

`Uint8Array<ArrayBuffer>`

---

### toString()

> **toString**(): `string`

Returns the string representation of this BitString.
Decodes the bytes as UTF-8 text.

#### Returns

`string`

The decoded string

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`toString`](../../../asn1/BitString/classes/BitString.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): [`BitString`](../../../asn1/BitString/classes/BitString.md)

Creates a BitString from an ASN.1 BIT STRING structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 BIT STRING to parse

#### Returns

[`BitString`](../../../asn1/BitString/classes/BitString.md)

A new BitString instance

#### Throws

Asn1ParseError if the ASN.1 structure is invalid

#### Inherited from

[`BitString`](../../../asn1/BitString/classes/BitString.md).[`fromAsn1`](../../../asn1/BitString/classes/BitString.md#fromasn1)

---

### fromCoordinates()

> `static` **fromCoordinates**(`x`, `y`): `ECPublicKey`

Creates an ECPublicKey from the X and Y coordinates of the point

#### Parameters

##### x

`Uint8Array<ArrayBuffer>`

The X coordinate of the point

##### y

`Uint8Array<ArrayBuffer>`

The Y coordinate of the point

#### Returns

`ECPublicKey`

An ECPublicKey object

---

### fromRaw()

> `static` **fromRaw**(`raw`): `ECPublicKey`

#### Parameters

##### raw

`Uint8Array<ArrayBuffer>`

#### Returns

`ECPublicKey`
