[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [keys/ECPrivateKey](../README.md) / ECPrivateKey

# Class: ECPrivateKey

Represents an EC private key according to RFC 5915.

ASN.1 Structure:

```
ECPrivateKey ::= SEQUENCE {
  version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
  privateKey     OCTET STRING,
  parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
  publicKey  [1] BIT STRING OPTIONAL
}
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`ECPrivateKey`\>

## Constructors

### Constructor

> **new ECPrivateKey**(`options`): `ECPrivateKey`

Creates a new ECPrivateKey

#### Parameters

##### options

###### namedCurve?

`string`

###### privateKey

`Uint8Array`

###### publicKey?

`Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`ECPrivateKey`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### namedCurve?

> `optional` **namedCurve**: `string`

The named curve OID (if parameters are present)
Most commonly this is a string like '1.2.840.10045.3.1.7' for P-256

---

### privateKey

> **privateKey**: `Uint8Array`

The private key value as an octet string

---

### publicKey?

> `optional` **publicKey**: `Uint8Array`\<`ArrayBufferLike`\>

The key component (if included)

---

### version

> **version**: `number` = `1`

The version of the EC private key structure (always 1)

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

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts the ECPrivateKey to an ASN.1 structure

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts the ECPrivateKey to a DER-encoded byte array

#### Returns

`Uint8Array`

#### Overrides

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

Converts the ECPrivateKey to a PEM-encoded string

#### Returns

`string`

#### Overrides

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

### forCurve()

> `static` **forCurve**(`curve`, `privateKey`, `publicKey?`): `ECPrivateKey`

Creates an ECPrivateKey for a specific named curve

#### Parameters

##### curve

`string`

The named curve OID (e.g., EC_CURVES.SECP256R1)

##### privateKey

`Uint8Array`

The private key value

##### publicKey?

`Uint8Array`\<`ArrayBufferLike`\>

Optional key value

#### Returns

`ECPrivateKey`

An ECPrivateKey object

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `ECPrivateKey`

Creates an ECPrivateKey from an ASN.1 structure

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`ECPrivateKey`

An ECPrivateKey object

---

### fromDer()

> `static` **fromDer**(`der`): `ECPrivateKey`

Creates an ECPrivateKey from a DER-encoded byte array

#### Parameters

##### der

`Uint8Array`

The DER-encoded ECPrivateKey

#### Returns

`ECPrivateKey`

An ECPrivateKey object

---

### fromPem()

> `static` **fromPem**(`pem`): `ECPrivateKey`

Creates an ECPrivateKey from a PEM-encoded string

#### Parameters

##### pem

`string`

The PEM-encoded ECPrivateKey

#### Returns

`ECPrivateKey`

An ECPrivateKey object
