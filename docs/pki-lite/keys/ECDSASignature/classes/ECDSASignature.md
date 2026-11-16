[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [keys/ECDSASignature](../README.md) / ECDSASignature

# Class: ECDSASignature

Represents an ECDSA signature, consisting of r and s components.
This follows the ASN.1 structure:

ECDSA-Sig-Value ::= SEQUENCE {
r INTEGER,
s INTEGER
}

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`ECDSASignature`\>

## Constructors

### Constructor

> **new ECDSASignature**(`options`): `ECDSASignature`

#### Parameters

##### options

###### r

`number` \| `Uint8Array`\<`ArrayBuffer`\> \| [`Integer`](../../../asn1/Integer/classes/Integer.md)

###### s

`number` \| `Uint8Array`\<`ArrayBuffer`\> \| [`Integer`](../../../asn1/Integer/classes/Integer.md)

#### Returns

`ECDSASignature`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### r

> `readonly` **r**: [`Integer`](../../../asn1/Integer/classes/Integer.md)

---

### s

> `readonly` **s**: [`Integer`](../../../asn1/Integer/classes/Integer.md)

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

> **toAsn1**(): `Sequence`

Convert to ASN.1 structure.

Note: ASN.1 DER encoding requires that INTEGER values with the high bit set
are padded with a leading 0x00 byte to ensure they're interpreted as positive.
This is handled by the Integer class.

#### Returns

`Sequence`

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

### toOriginalDer()

> **toOriginalDer**(): `Uint8Array`\<`ArrayBuffer`\>

The DER this object was parsed from, if it has not been changed since; otherwise
[toDer](../../../core/PkiBase/classes/PkiBase.md#toder). Use it for the bytes a signature covers (a certificate's or CRL's
TBS part): re-encoding a parsed value does not always give back the same bytes (a
GeneralizedTime before 2050 becomes a UTCTime, a string changes type, ...), and any
difference breaks the signature. Only types that keep their encoding when parsed
(TBSCertificate, TBSCertList, CertificateRequestInfo) have one to return.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The original encoding, or the current one

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toOriginalDer`](../../../core/PkiBase/classes/PkiBase.md#tooriginalder)

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

### toRaw()

> **toRaw**(`componentLength?`): `Uint8Array`\<`ArrayBuffer`\>

Convert to raw format (r || s), as used by WebCrypto.

#### Parameters

##### componentLength?

`number`

The byte length of r and s, i.e. of the curve order (32 for
P-256, 48 for P-384, 66 for P-521). Pass it whenever it is known: r and s are often
shorter than that, and without it they are only padded to the longer of the two.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

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

> `static` **fromAsn1**(`asn1`): `ECDSASignature`

Parse from ASN.1 structure.

#### Parameters

##### asn1

`AsnType`

#### Returns

`ECDSASignature`

---

### fromDer()

> `static` **fromDer**(`der`): `ECDSASignature`

Parse from DER format.

#### Parameters

##### der

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

`ECDSASignature`

---

### fromRaw()

> `static` **fromRaw**(`raw`): `ECDSASignature`

Parse from raw format (r || s).

#### Parameters

##### raw

`Uint8Array`\<`ArrayBuffer`\>

Raw signature bytes (r || s)

#### Returns

`ECDSASignature`
