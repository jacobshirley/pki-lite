[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [algorithms/RSASSAPSSParams](../README.md) / RSASSAPSSParams

# Class: RSASSAPSSParams

RSASSA-PSS-params ::= SEQUENCE {
hashAlgorithm [0] HashAlgorithm DEFAULT sha1,
maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
saltLength [2] INTEGER DEFAULT 20,
trailerField [3] TrailerField DEFAULT trailerFieldBC
}

HashAlgorithm ::= AlgorithmIdentifier

MaskGenAlgorithm ::= AlgorithmIdentifier

TrailerField ::= INTEGER { trailerFieldBC(1) }

Implementation based on RFC 3447 (PKCS #1 v2.1)

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`RSASSAPSSParams`\>

## Constructors

### Constructor

> **new RSASSAPSSParams**(`options`): `RSASSAPSSParams`

Creates a new instance of RSASSAPSSParams

#### Parameters

##### options

###### hashAlgorithm?

[`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### maskGenAlgorithm?

[`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### saltLength?

`number`

###### trailerField?

`number`

#### Returns

`RSASSAPSSParams`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### hashAlgorithm?

> `optional` **hashAlgorithm**: [`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

---

### maskGenAlgorithm?

> `optional` **maskGenAlgorithm**: [`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

---

### saltLength?

> `optional` **saltLength**: `number`

---

### trailerField?

> `optional` **trailerField**: `number`

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

### getEffectiveHashAlgorithm()

> **getEffectiveHashAlgorithm**(): [`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Get effective hash algorithm (either specified or default)

#### Returns

[`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

---

### getEffectiveMaskGenAlgorithm()

> **getEffectiveMaskGenAlgorithm**(): [`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Get effective mask generation algorithm (either specified or default)

#### Returns

[`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

---

### getEffectiveSaltLength()

> **getEffectiveSaltLength**(): `number`

Get effective salt length (either specified or default)

#### Returns

`number`

---

### getEffectiveTrailerField()

> **getEffectiveTrailerField**(): `number`

Get effective trailer field (either specified or default)

#### Returns

`number`

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

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts to ASN.1 structure

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

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

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toJSON`](../../../core/PkiBase/classes/PkiBase.md#tojson)

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

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toString`](../../../core/PkiBase/classes/PkiBase.md#tostring)

---

### createDefault()

> `static` **createDefault**(): `RSASSAPSSParams`

Creates a default instance with all parameters set to their defaults

#### Returns

`RSASSAPSSParams`

---

### defaultHashAlgorithm()

> `static` **defaultHashAlgorithm**(): [`DigestAlgorithmIdentifier`](../../AlgorithmIdentifier/classes/DigestAlgorithmIdentifier.md)

#### Returns

[`DigestAlgorithmIdentifier`](../../AlgorithmIdentifier/classes/DigestAlgorithmIdentifier.md)

---

### defaultMaskGenAlgorithm()

> `static` **defaultMaskGenAlgorithm**(): [`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

#### Returns

[`AlgorithmIdentifier`](../../AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

---

### defaultSaltLength()

> `static` **defaultSaltLength**(): `number`

#### Returns

`number`

---

### defaultTrailerField()

> `static` **defaultTrailerField**(): `number`

#### Returns

`number`

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `RSASSAPSSParams`

Parse from ASN.1 structure

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`RSASSAPSSParams`
