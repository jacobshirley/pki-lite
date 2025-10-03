[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [algorithms/AlgorithmIdentifier](../README.md) / SignatureAlgorithmIdentifier

# Class: SignatureAlgorithmIdentifier

Represents a signature algorithm identifier.

## Asn

```asn
SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
```

## Extends

- [`AlgorithmIdentifier`](AlgorithmIdentifier.md)

## Constructors

### Constructor

> **new SignatureAlgorithmIdentifier**(`options`): `SignatureAlgorithmIdentifier`

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

`SignatureAlgorithmIdentifier`

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`constructor`](AlgorithmIdentifier.md#constructor)

## Properties

### algorithm

> **algorithm**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

The algorithm object identifier (OID).

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`algorithm`](AlgorithmIdentifier.md#algorithm)

---

### noPadding

> `protected` **noPadding**: `boolean` = `false`

**`Internal`**

Internal flag indicating whether this algorithm uses padding.

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`noPadding`](AlgorithmIdentifier.md#nopadding)

---

### parameters?

> `optional` **parameters**: [`Any`](../../../asn1/Any/classes/Any.md)

Algorithm-specific parameters (optional).
The format depends on the specific algorithm.

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`parameters`](AlgorithmIdentifier.md#parameters)

## Accessors

### friendlyName

#### Get Signature

> **get** **friendlyName**(): `string`

Gets a human-readable name for this algorithm.
Returns the friendly name if known, otherwise the OID.

##### Returns

`string`

The algorithm name (e.g., "rsaEncryption", "sha256")

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`friendlyName`](AlgorithmIdentifier.md#friendlyname)

---

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`pemHeader`](AlgorithmIdentifier.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`pkiType`](AlgorithmIdentifier.md#pkitype)

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

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`equals`](AlgorithmIdentifier.md#equals)

---

### getEcNamedCurve()

> **getEcNamedCurve**(`publicKeyInfo?`): [`NamedCurve`](../../../core/crypto/types/type-aliases/NamedCurve.md)

#### Parameters

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

#### Returns

[`NamedCurve`](../../../core/crypto/types/type-aliases/NamedCurve.md)

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`getEcNamedCurve`](AlgorithmIdentifier.md#getecnamedcurve)

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

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`parseAs`](AlgorithmIdentifier.md#parseas)

---

### sign()

> **sign**(`data`, `privateKeyInfo`): `Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> | [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\>

##### privateKeyInfo

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

#### Returns

`Promise`\<`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>\>

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this AlgorithmIdentifier to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 SEQUENCE structure

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`toAsn1`](AlgorithmIdentifier.md#toasn1)

---

### toAsymmetricEncryptionAlgorithmParams()

> **toAsymmetricEncryptionAlgorithmParams**(`publicKeyInfo?`): [`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Parameters

##### publicKeyInfo?

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

#### Returns

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

---

### toDer()

> **toDer**(): `Uint8Array<ArrayBuffer>`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array<ArrayBuffer>`

The DER-encoded bytes of this object

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`toDer`](AlgorithmIdentifier.md#toder)

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

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`toHumanString`](AlgorithmIdentifier.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`toJSON`](AlgorithmIdentifier.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`toPem`](AlgorithmIdentifier.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`toString`](AlgorithmIdentifier.md#tostring)

---

### verify()

> **verify**(`data`, `signature`, `publicKeyInfo`): `Promise`\<`boolean`\>

#### Parameters

##### data

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> | [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\>

##### signature

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\> | [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\>

##### publicKeyInfo

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

#### Returns

`Promise`\<`boolean`\>

---

### contentEncryptionAlgorithm()

> `static` **contentEncryptionAlgorithm**(`encryptionParams`): [`ContentEncryptionAlgorithmIdentifier`](ContentEncryptionAlgorithmIdentifier.md)

#### Parameters

##### encryptionParams

[`SymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/SymmetricEncryptionAlgorithmParams.md)

#### Returns

[`ContentEncryptionAlgorithmIdentifier`](ContentEncryptionAlgorithmIdentifier.md)

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`contentEncryptionAlgorithm`](AlgorithmIdentifier.md#contentencryptionalgorithm)

---

### digestAlgorithm()

> `static` **digestAlgorithm**(`params`): [`DigestAlgorithmIdentifier`](DigestAlgorithmIdentifier.md)

#### Parameters

##### params

[`HashAlgorithm`](../../../core/crypto/types/type-aliases/HashAlgorithm.md)

#### Returns

[`DigestAlgorithmIdentifier`](DigestAlgorithmIdentifier.md)

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`digestAlgorithm`](AlgorithmIdentifier.md#digestalgorithm)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SignatureAlgorithmIdentifier`

Creates an AlgorithmIdentifier from an ASN.1 structure

#### Parameters

##### asn1

[`BaseBlock`](../../../core/PkiBase/namespaces/asn1js/classes/BaseBlock.md)

The ASN.1 structure

#### Returns

`SignatureAlgorithmIdentifier`

An AlgorithmIdentifier

#### Overrides

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`fromAsn1`](AlgorithmIdentifier.md#fromasn1)

---

### fromDer()

> `static` **fromDer**(`bytes`): `SignatureAlgorithmIdentifier`

#### Parameters

##### bytes

`Uint8Array<ArrayBuffer>`

#### Returns

`SignatureAlgorithmIdentifier`

#### Overrides

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`fromDer`](AlgorithmIdentifier.md#fromder)

---

### getEcCurveParameters()

> `static` **getEcCurveParameters**(`encryptionParams`): [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`getEcCurveParameters`](AlgorithmIdentifier.md#geteccurveparameters)

---

### keyEncryptionAlgorithm()

> `static` **keyEncryptionAlgorithm**(`encryptionParams`): [`KeyEncryptionAlgorithmIdentifier`](KeyEncryptionAlgorithmIdentifier.md)

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

[`KeyEncryptionAlgorithmIdentifier`](KeyEncryptionAlgorithmIdentifier.md)

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`keyEncryptionAlgorithm`](AlgorithmIdentifier.md#keyencryptionalgorithm)

---

### randomBytes()

> `static` **randomBytes**(`length`): `Uint8Array<ArrayBuffer>`

#### Parameters

##### length

`number`

#### Returns

`Uint8Array<ArrayBuffer>`

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`randomBytes`](AlgorithmIdentifier.md#randombytes)

---

### signatureAlgorithm()

> `static` **signatureAlgorithm**(`encryptionParams`): `SignatureAlgorithmIdentifier`

#### Parameters

##### encryptionParams

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

`SignatureAlgorithmIdentifier`

#### Inherited from

[`AlgorithmIdentifier`](AlgorithmIdentifier.md).[`signatureAlgorithm`](AlgorithmIdentifier.md#signaturealgorithm)
