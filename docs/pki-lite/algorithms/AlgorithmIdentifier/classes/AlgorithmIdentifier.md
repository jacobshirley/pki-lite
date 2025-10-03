[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [algorithms/AlgorithmIdentifier](../README.md) / AlgorithmIdentifier

# Class: AlgorithmIdentifier

Represents an algorithm identifier used throughout PKI standards.

An AlgorithmIdentifier specifies a cryptographic algorithm along with any
algorithm-specific parameters. It's used for signature algorithms, encryption
algorithms, hash functions, and key derivation functions in X.509 certificates,
PKCS structures, and other PKI objects.

## Asn

```asn
AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL
}
```

## Example

```typescript
// RSA with PKCS#1 v1.5 padding
const rsaAlg = new AlgorithmIdentifier({
    algorithm: '1.2.840.113549.1.1.1', // rsaEncryption OID
})

// RSA-PSS with specific parameters
const rsaPssAlg = new AlgorithmIdentifier({
    algorithm: '1.2.840.113549.1.1.10', // rsassa-pss OID
    parameters: new RSASSAPSSParams({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: OIDs.sha256 }),
        saltLength: 32,
    }),
})

// Check algorithm type
console.log(rsaAlg.friendlyName) // "rsaEncryption"
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`AlgorithmIdentifier`\>

## Extended by

- [`DigestAlgorithmIdentifier`](DigestAlgorithmIdentifier.md)
- [`SignatureAlgorithmIdentifier`](SignatureAlgorithmIdentifier.md)
- [`KeyEncryptionAlgorithmIdentifier`](KeyEncryptionAlgorithmIdentifier.md)
- [`ContentEncryptionAlgorithmIdentifier`](ContentEncryptionAlgorithmIdentifier.md)
- [`PSourceAlgorithm`](PSourceAlgorithm.md)

## Constructors

### Constructor

> **new AlgorithmIdentifier**(`options`): `AlgorithmIdentifier`

Creates a new AlgorithmIdentifier instance.

#### Parameters

##### options

Configuration object

###### algorithm

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

The algorithm OID as string or ObjectIdentifier

###### parameters?

[`Asn1Any`](../../../core/PkiBase/type-aliases/Asn1Any.md)

Optional algorithm-specific parameters

#### Returns

`AlgorithmIdentifier`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### algorithm

> **algorithm**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

The algorithm object identifier (OID).

---

### noPadding

> `protected` **noPadding**: `boolean` = `false`

**`Internal`**

Internal flag indicating whether this algorithm uses padding.

---

### parameters?

> `optional` **parameters**: [`Any`](../../../asn1/Any/classes/Any.md)

Algorithm-specific parameters (optional).
The format depends on the specific algorithm.

## Accessors

### friendlyName

#### Get Signature

> **get** **friendlyName**(): `string`

Gets a human-readable name for this algorithm.
Returns the friendly name if known, otherwise the OID.

##### Returns

`string`

The algorithm name (e.g., "rsaEncryption", "sha256")

---

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

### getEcNamedCurve()

> **getEcNamedCurve**(`publicKeyInfo?`): [`NamedCurve`](../../../core/crypto/types/type-aliases/NamedCurve.md)

#### Parameters

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

#### Returns

[`NamedCurve`](../../../core/crypto/types/type-aliases/NamedCurve.md)

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

Converts this AlgorithmIdentifier to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 SEQUENCE structure

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

### contentEncryptionAlgorithm()

> `static` **contentEncryptionAlgorithm**(`encryptionParams`): [`ContentEncryptionAlgorithmIdentifier`](ContentEncryptionAlgorithmIdentifier.md)

#### Parameters

##### encryptionParams

[`SymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

#### Returns

[`ContentEncryptionAlgorithmIdentifier`](ContentEncryptionAlgorithmIdentifier.md)

---

### digestAlgorithm()

> `static` **digestAlgorithm**(`params`): [`DigestAlgorithmIdentifier`](DigestAlgorithmIdentifier.md)

#### Parameters

##### params

[`HashAlgorithm`](../../../core/crypto/types/type-aliases/HashAlgorithm.md)

#### Returns

[`DigestAlgorithmIdentifier`](DigestAlgorithmIdentifier.md)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `AlgorithmIdentifier`

Creates an AlgorithmIdentifier from an ASN.1 structure

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`AlgorithmIdentifier`

An AlgorithmIdentifier

---

### fromDer()

> `static` **fromDer**(`bytes`): `AlgorithmIdentifier`

#### Parameters

##### bytes

`Uint8Array`

#### Returns

`AlgorithmIdentifier`

---

### getEcCurveParameters()

> `static` **getEcCurveParameters**(`encryptionParams`): [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

---

### keyEncryptionAlgorithm()

> `static` **keyEncryptionAlgorithm**(`encryptionParams`): [`KeyEncryptionAlgorithmIdentifier`](KeyEncryptionAlgorithmIdentifier.md)

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

[`KeyEncryptionAlgorithmIdentifier`](KeyEncryptionAlgorithmIdentifier.md)

---

### randomBytes()

> `static` **randomBytes**(`length`): `Uint8Array`\<`ArrayBuffer`\>

#### Parameters

##### length

`number`

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

---

### signatureAlgorithm()

> `static` **signatureAlgorithm**(`encryptionParams`): [`SignatureAlgorithmIdentifier`](SignatureAlgorithmIdentifier.md)

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

[`SignatureAlgorithmIdentifier`](SignatureAlgorithmIdentifier.md)
