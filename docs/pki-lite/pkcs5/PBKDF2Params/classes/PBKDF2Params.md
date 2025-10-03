[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs5/PBKDF2Params](../README.md) / PBKDF2Params

# Class: PBKDF2Params

Represents PBKDF2-params structure.

## Asn

```asn
PBKDF2-params ::= SEQUENCE {
  salt CHOICE {
    specified OCTET STRING,
    otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
  },
  iterationCount INTEGER (1..MAX),
  keyLength INTEGER (1..MAX) OPTIONAL,
  prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
    algid-hmacWithSHA1
}
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`PBKDF2Params`\>

## Constructors

### Constructor

> **new PBKDF2Params**(`options`): `PBKDF2Params`

#### Parameters

##### options

###### iterationCount

`number`

###### keyLength?

`number`

###### prf?

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### salt

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`OctetString`](../../../asn1/OctetString/classes/OctetString.md) \| [`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

#### Returns

`PBKDF2Params`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### iterationCount

> **iterationCount**: `number`

---

### keyLength?

> `optional` **keyLength**: `number`

---

### prf

> **prf**: [`DigestAlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/DigestAlgorithmIdentifier.md)

---

### salt

> **salt**: [`OctetString`](../../../asn1/OctetString/classes/OctetString.md) \| [`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

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

> **toAsn1**(): [`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Sequence`](../../../core/PkiBase/namespaces/asn1js/classes/Sequence.md)

The ASN.1 representation of this object

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

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `PBKDF2Params`

#### Parameters

##### asn1

[`BaseBlock`](../../../core/PkiBase/namespaces/asn1js/classes/BaseBlock.md)

#### Returns

`PBKDF2Params`
