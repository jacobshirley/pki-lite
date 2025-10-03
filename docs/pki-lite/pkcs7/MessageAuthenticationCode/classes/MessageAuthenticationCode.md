[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/MessageAuthenticationCode](../README.md) / MessageAuthenticationCode

# Class: MessageAuthenticationCode

Message Authentication Code

## Asn

```asn
MessageAuthenticationCode ::= OCTET STRING
```

## Extends

- [`OctetString`](../../../asn1/OctetString/classes/OctetString.md)

## Constructors

### Constructor

> **new MessageAuthenticationCode**(`options`): `MessageAuthenticationCode`

#### Parameters

##### options

###### bytes

`string` \| [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\> \| `Uint8Array`\<`ArrayBufferLike`\> \| [`OctetString`](../../../asn1/OctetString/classes/OctetString.md) \| [`PkiSequence`](../../../core/PkiBase/classes/PkiSequence.md)\<`any`\> \| [`PkiSet`](../../../core/PkiBase/classes/PkiSet.md)\<`any`\>

#### Returns

`MessageAuthenticationCode`

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`constructor`](../../../asn1/OctetString/classes/OctetString.md#constructor)

## Properties

### bytes

> **bytes**: `Uint8Array`\<`ArrayBuffer`\>

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`bytes`](../../../asn1/OctetString/classes/OctetString.md#bytes)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`pemHeader`](../../../asn1/OctetString/classes/OctetString.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`pkiType`](../../../asn1/OctetString/classes/OctetString.md#pkitype)

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

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`equals`](../../../asn1/OctetString/classes/OctetString.md#equals)

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

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`parseAs`](../../../asn1/OctetString/classes/OctetString.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this PKI object to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 representation of this object

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toAsn1`](../../../asn1/OctetString/classes/OctetString.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toDer`](../../../asn1/OctetString/classes/OctetString.md#toder)

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

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toHumanString`](../../../asn1/OctetString/classes/OctetString.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toJSON`](../../../asn1/OctetString/classes/OctetString.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toPem`](../../../asn1/OctetString/classes/OctetString.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toString`](../../../asn1/OctetString/classes/OctetString.md#tostring)

---

### toUint8Array()

> **toUint8Array**(): `Uint8Array`\<`ArrayBuffer`\>

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`toUint8Array`](../../../asn1/OctetString/classes/OctetString.md#touint8array)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `MessageAuthenticationCode`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`MessageAuthenticationCode`

#### Overrides

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`fromAsn1`](../../../asn1/OctetString/classes/OctetString.md#fromasn1)

---

### fromDer()

> `static` **fromDer**(`der`): [`OctetString`](../../../asn1/OctetString/classes/OctetString.md)

#### Parameters

##### der

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md)

#### Inherited from

[`OctetString`](../../../asn1/OctetString/classes/OctetString.md).[`fromDer`](../../../asn1/OctetString/classes/OctetString.md#fromder)
