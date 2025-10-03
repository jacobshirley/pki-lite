[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/GeneralName](../README.md) / registeredID

# Class: registeredID

Represents an ASN.1 OBJECT IDENTIFIER value.

Object Identifiers (OIDs) are hierarchically structured identifiers used throughout
PKI and cryptographic standards to uniquely identify algorithms, attributes, and
other objects. They are represented as dot-separated sequences of integers.

## Asn

```asn
OBJECT IDENTIFIER ::= <value>
```

## Example

```typescript
// Create an OID for RSA encryption
const rsaOid = new ObjectIdentifier({ value: '1.2.840.113549.1.1.1' })

// Check if it matches a known OID
if (rsaOid.is('1.2.840.113549.1.1.1')) {
    console.log('RSA algorithm detected')
}

// Get friendly name if available
console.log(rsaOid.friendlyName) // "rsaEncryption"
```

## Extends

- [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

## Constructors

### Constructor

> **new registeredID**(`options`): `registeredID`

Creates a new ObjectIdentifier instance.

#### Parameters

##### options

Configuration object

###### value

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md) \| [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

The OID value as string, ObjectIdentifier, or object with toString()

#### Returns

`registeredID`

#### Throws

Error if value is null, undefined, or invalid

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`constructor`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#constructor)

## Properties

### value

> **value**: `string`

The dot-separated OID value (e.g., "1.2.840.113549.1.1.1").

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`value`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#value)

## Accessors

### friendlyName

#### Get Signature

> **get** **friendlyName**(): `string`

Gets a human-readable name for this OID if available.
Falls back to the OID value if no friendly name is known.

##### Returns

`string`

A friendly name (e.g., "rsaEncryption") or the OID value

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`friendlyName`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#friendlyname)

---

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`pemHeader`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`pkiType`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#pkitype)

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

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`equals`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#equals)

---

### is()

> **is**(`other`): `boolean`

Checks if this OID equals another OID.

#### Parameters

##### other

The OID to compare with (ObjectIdentifier instance or string)

`string` | [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Returns

`boolean`

true if the OIDs are equal, false otherwise

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`is`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#is)

---

### isNot()

> **isNot**(`other`): `boolean`

Checks if this OID does not equal another OID.

#### Parameters

##### other

The OID to compare with (ObjectIdentifier instance or string)

`string` | [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

#### Returns

`boolean`

true if the OIDs are different, false otherwise

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`isNot`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#isnot)

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

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`parseAs`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#parseas)

---

### toAsn1()

> **toAsn1**(): `Sequence`

Converts this ObjectIdentifier to its ASN.1 representation.

#### Returns

`Sequence`

The ASN.1 OBJECT IDENTIFIER structure

#### Overrides

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`toAsn1`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`toDer`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#toder)

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

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`toHumanString`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`toJSON`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`toPem`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#topem)

---

### toString()

> **toString**(): `string`

Returns the string representation of this OID.

#### Returns

`string`

The dot-separated OID value

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`toString`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `registeredID`

Creates an ObjectIdentifier from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 OBJECT IDENTIFIER to parse

#### Returns

`registeredID`

A new ObjectIdentifier instance

#### Throws

Asn1ParseError if the ASN.1 structure is invalid

#### Overrides

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`fromAsn1`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#fromasn1)

---

### fromDer()

> `static` **fromDer**(`bytes`): [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Creates an ObjectIdentifier from DER-encoded bytes.

#### Parameters

##### bytes

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded OBJECT IDENTIFIER bytes

#### Returns

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

A new ObjectIdentifier instance

#### Inherited from

[`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md).[`fromDer`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md#fromder)
