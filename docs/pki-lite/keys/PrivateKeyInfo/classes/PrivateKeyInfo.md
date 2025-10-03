[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [keys/PrivateKeyInfo](../README.md) / PrivateKeyInfo

# Class: PrivateKeyInfo

Represents a private key in PKCS#8 format.

PrivateKeyInfo is the standard format for encoding private keys as defined
in PKCS#8. It includes the algorithm identifier, the private key material,
and optional attributes. This format is algorithm-agnostic and can represent
RSA, ECDSA, EdDSA, and other types of private keys.

## Asn

```asn
PrivateKeyInfo ::= SEQUENCE {
     version                 Version,
     privateKeyAlgorithm     AlgorithmIdentifier,
     privateKey              OCTET STRING,
     attributes          [0] IMPLICIT Attributes OPTIONAL
}
```

## Example

```typescript
// Create a private key info structure
const privateKeyInfo = new PrivateKeyInfo({
    algorithm: new AlgorithmIdentifier({
        algorithm: OIDs.rsaEncryption,
    }),
    privateKey: rsaPrivateKeyBytes,
})

// Load from PEM
const pem = '-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----'
const keyInfo = PrivateKeyInfo.fromPem(pem)

// Extract the actual private key
const rsaKey = keyInfo.extractRSAPrivateKey()
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`PrivateKeyInfo`\>

## Constructors

### Constructor

> **new PrivateKeyInfo**(`options`): `PrivateKeyInfo`

Creates a new PrivateKeyInfo instance.

#### Parameters

##### options

Configuration object

###### algorithm

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The private key algorithm identifier

###### attributes?

[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

Optional key attributes

###### privateKey

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> \| [`OctetString`](../../../asn1/OctetString/classes/OctetString.md)

The private key bytes or OctetString

###### version?

`number`

Version number (defaults to 0)

#### Returns

`PrivateKeyInfo`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### algorithm

> **algorithm**: [`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Algorithm identifier specifying the private key algorithm and parameters.

---

### attributes?

> `optional` **attributes**: [`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

Optional attributes providing additional key metadata.

---

### privateKey

> **privateKey**: [`OctetString`](../../../asn1/OctetString/classes/OctetString.md)

The private key material as an OCTET STRING.
The format of this data depends on the algorithm.

---

### version

> **version**: `number`

Version number (usually 0 for PKCS#8 v1).

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

### getEcPrivateKey()

> **getEcPrivateKey**(): [`ECPrivateKey`](../../ECPrivateKey/classes/ECPrivateKey.md)

#### Returns

[`ECPrivateKey`](../../ECPrivateKey/classes/ECPrivateKey.md)

---

### getPrivateKey()

> **getPrivateKey**(): [`RSAPrivateKey`](../../RSAPrivateKey/classes/RSAPrivateKey.md) \| [`ECPrivateKey`](../../ECPrivateKey/classes/ECPrivateKey.md)

#### Returns

[`RSAPrivateKey`](../../RSAPrivateKey/classes/RSAPrivateKey.md) \| [`ECPrivateKey`](../../ECPrivateKey/classes/ECPrivateKey.md)

---

### getRsaPrivateKey()

> **getRsaPrivateKey**(): [`RSAPrivateKey`](../../RSAPrivateKey/classes/RSAPrivateKey.md)

#### Returns

[`RSAPrivateKey`](../../RSAPrivateKey/classes/RSAPrivateKey.md)

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

Converts this PrivateKeyInfo to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 SEQUENCE structure

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

> `static` **fromAsn1**(`asn1`): `PrivateKeyInfo`

Creates a PrivateKeyInfo from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`PrivateKeyInfo`

A PrivateKeyInfo

---

### fromDer()

> `static` **fromDer**(`der`): `PrivateKeyInfo`

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

#### Returns

`PrivateKeyInfo`

---

### fromPem()

> `static` **fromPem**(`pem`): `PrivateKeyInfo`

#### Parameters

##### pem

`string`

#### Returns

`PrivateKeyInfo`
