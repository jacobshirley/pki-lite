[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/SignerInfo](../README.md) / SignerInfo

# Class: SignerInfo

Represents a CMS SignerInfo structure as defined in RFC 5652.

## Asn

```asn
SignerInfo ::= SEQUENCE {
     version CMSVersion,
     sid SignerIdentifier,
     digestAlgorithm DigestAlgorithmIdentifier,
     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
     signatureAlgorithm SignatureAlgorithmIdentifier,
     signature SignatureValue,
     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
}

SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
DigestAlgorithmIdentifier ::= AlgorithmIdentifier
SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
SignatureValue ::= OCTET STRING
SubjectKeyIdentifier ::= OCTET STRING
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`SignerInfo`\>

## Constructors

### Constructor

> **new SignerInfo**(`options`): `SignerInfo`

#### Parameters

##### options

###### digestAlgorithm

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### sid

[`SignerIdentifier`](../../SignerIdentifier/type-aliases/SignerIdentifier.md)

###### signature

`Uint8Array`\<`ArrayBuffer`\>

###### signatureAlgorithm

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

###### signedAttrs?

[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

###### unsignedAttrs?

[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

###### version

`number`

#### Returns

`SignerInfo`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### digestAlgorithm

> **digestAlgorithm**: [`DigestAlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/DigestAlgorithmIdentifier.md)

---

### sid

> **sid**: [`SignerIdentifier`](../../SignerIdentifier/type-aliases/SignerIdentifier.md)

---

### signature

> **signature**: `Uint8Array`\<`ArrayBuffer`\>

---

### signatureAlgorithm

> **signatureAlgorithm**: [`SignatureAlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/SignatureAlgorithmIdentifier.md)

---

### signedAttrs?

> `optional` **signedAttrs**: [`SignedAttributes`](SignedAttributes.md)

---

### unsignedAttrs?

> `optional` **unsignedAttrs**: [`UnsignedAttributes`](UnsignedAttributes.md)

---

### version

> **version**: `number`

---

### SignedAttributes

> `static` **SignedAttributes**: _typeof_ [`SignedAttributes`](SignedAttributes.md)

---

### UnsignedAttributes

> `static` **UnsignedAttributes**: _typeof_ [`UnsignedAttributes`](UnsignedAttributes.md)

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

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 representation of this object

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

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

### verify()

> **verify**(`options`): `Promise`\<\{ `valid`: `true`; \} \| \{ `reasons`: `string`[]; `valid`: `false`; \}\>

#### Parameters

##### options

###### data?

`Uint8Array`\<`ArrayBuffer`\>

###### publicKeyInfo

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

#### Returns

`Promise`\<\{ `valid`: `true`; \} \| \{ `reasons`: `string`[]; `valid`: `false`; \}\>

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SignerInfo`

Creates a SignerInfo from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`SignerInfo`

A SignerInfo object

---

### fromDer()

> `static` **fromDer**(`derBytes`): `SignerInfo`

#### Parameters

##### derBytes

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

`SignerInfo`
