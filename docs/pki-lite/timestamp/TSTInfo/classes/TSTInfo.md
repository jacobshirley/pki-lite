[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [timestamp/TSTInfo](../README.md) / TSTInfo

# Class: TSTInfo

TSTInfo structure for RFC 3161 Time-Stamp Protocol.

The TSTInfo is the core content of a timestamp token. It contains the
actual timestamp along with the hashed data and policy information.
This structure is encapsulated within a SignedData content type.

## Asn

```asn
TSTInfo ::= SEQUENCE  {
    version                      INTEGER  { v1(1) },
    policy                       TSAPolicyId,
    messageImprint               MessageImprint,
      -- MUST have the same value as the similar field in
      -- TimeStampReq
    serialNumber                 INTEGER,
     -- Time-Stamping users MUST be ready to accommodate integers
     -- up to 160 bits.
    genTime                      GeneralizedTime,
    accuracy                     Accuracy                 OPTIONAL,
    ordering                     BOOLEAN             DEFAULT FALSE,
    nonce                        INTEGER                  OPTIONAL,
      -- MUST be present if the similar field was present
      -- in TimeStampReq.  In that case it MUST have the same value.
    tsa                          [0] GeneralName          OPTIONAL,
    extensions                   [1] IMPLICIT Extensions  OPTIONAL   }

TSAPolicyId ::= OBJECT IDENTIFIER
```

## See

RFC 3161 Section 2.4.2 - TSTInfo Structure

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`TSTInfo`\>

## Constructors

### Constructor

> **new TSTInfo**(`options`): `TSTInfo`

Creates a new TSTInfo instance.

#### Parameters

##### options

Configuration object for the timestamp info

###### accuracy?

[`Accuracy`](Accuracy.md)

Optional accuracy specification

###### extensions?

[`Extension`](../../../x509/Extension/classes/Extension.md)[]

Optional extensions

###### genTime

`Date`

Generation time of the timestamp

###### messageImprint

[`MessageImprint`](../../MessageImprint/classes/MessageImprint.md)

Hash imprint that was timestamped

###### nonce?

`Uint8Array`\<`ArrayBuffer`\>

Optional nonce (must match request if present)

###### ordering?

`boolean`

Whether timestamps are ordered

###### policy

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

TSA policy OID

###### serialNumber

`Uint8Array`\<`ArrayBuffer`\>

Unique serial number (up to 160 bits)

###### tsa?

[`GeneralName`](../../../x509/GeneralName/type-aliases/GeneralName.md)

Optional TSA identity

###### version?

`number`

Protocol version, defaults to 1

#### Returns

`TSTInfo`

#### Example

```typescript
const tstInfo = new TSTInfo({
    policy: '1.3.6.1.4.1.123.456.1',
    messageImprint: messageImprint,
    serialNumber: new Uint8Array([1, 2, 3, 4]),
    genTime: new Date(),
    accuracy: new Accuracy({ seconds: 1 }),
    ordering: false,
})
```

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### accuracy?

> `optional` **accuracy**: [`Accuracy`](Accuracy.md)

Optional accuracy of the timestamp

---

### extensions?

> `optional` **extensions**: [`Extension`](../../../x509/Extension/classes/Extension.md)[]

Optional extensions

---

### genTime

> **genTime**: `Date`

Time at which the timestamp was generated

---

### messageImprint

> **messageImprint**: [`MessageImprint`](../../MessageImprint/classes/MessageImprint.md)

Hash of the data that was timestamped

---

### nonce?

> `optional` **nonce**: `Uint8Array`\<`ArrayBuffer`\>

Optional nonce from the request

---

### ordering

> **ordering**: `boolean` = `false`

Whether timestamps are ordered (default false)

---

### policy

> **policy**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

TSA policy under which the timestamp was issued

---

### serialNumber

> **serialNumber**: `Uint8Array`\<`ArrayBuffer`\>

Unique serial number for this timestamp

---

### tsa?

> `optional` **tsa**: [`GeneralName`](../../../x509/GeneralName/type-aliases/GeneralName.md)

Optional TSA identity

---

### version

> **version**: `number`

Version of the TSTInfo format, currently always 1

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

Converts the TSTInfo to its ASN.1 representation.

Creates a SEQUENCE containing all the timestamp info fields in the proper order
according to RFC 3161 specification.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

ASN.1 structure representing the timestamp info

#### Example

```typescript
const asn1 = tstInfo.toAsn1()
const der = asn1.toBER(false)
```

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

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `TSTInfo`

Creates a TSTInfo from an ASN.1 structure.

Parses the ASN.1 SEQUENCE and extracts all optional and required fields
according to RFC 3161 specification.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure to parse

#### Returns

`TSTInfo`

The parsed TSTInfo object

#### Throws

Asn1ParseError if the ASN.1 structure is invalid

#### Example

```typescript
const asn1 = derToAsn1(tstInfoBytes)
const tstInfo = TSTInfo.fromAsn1(asn1)
console.log(tstInfo.genTime)
console.log(tstInfo.messageImprint.hashAlgorithm)
```

---

### fromDer()

> `static` **fromDer**(`bytes`): `TSTInfo`

#### Parameters

##### bytes

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

`TSTInfo`
