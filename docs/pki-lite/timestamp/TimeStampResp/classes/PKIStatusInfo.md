[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [timestamp/TimeStampResp](../README.md) / PKIStatusInfo

# Class: PKIStatusInfo

Status information for a timestamp request/response.

PKIStatusInfo provides detailed information about the processing of a timestamp
request, including success/failure status, optional descriptive text, and
specific failure reasons when applicable.

## Asn

PKIStatusInfo ::= SEQUENCE {
status PKIStatus,
statusString PKIFreeText OPTIONAL,
failInfo PKIFailureInfo OPTIONAL }

## Example

```typescript
// Success status
const successStatus = new PKIStatusInfo({
    status: PKIStatus.GRANTED,
})

// Failure status with details
const failureStatus = new PKIStatusInfo({
    status: PKIStatus.REJECTION,
    statusString: new PKIFreeText({ texts: ['Invalid algorithm'] }),
    failInfo: PKIFailureInfo.BAD_ALG,
})

if (statusInfo.isSuccess()) {
    console.log('Request was successful')
} else {
    console.log('Request failed:', statusInfo.getStatusDescription())
}
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`PKIStatusInfo`\>

## Constructors

### Constructor

> **new PKIStatusInfo**(`options`): `PKIStatusInfo`

Creates a new PKIStatusInfo instance.

#### Parameters

##### options

Configuration object

###### failInfo?

[`PKIFailureInfo`](../type-aliases/PKIFailureInfo.md)

Optional failure information

###### status

[`PKIStatus`](../type-aliases/PKIStatus.md)

The PKI status code

###### statusString?

[`PKIFreeText`](PKIFreeText.md)

Optional descriptive text

#### Returns

`PKIStatusInfo`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### failInfo?

> `optional` **failInfo**: [`PKIFailureInfo`](../type-aliases/PKIFailureInfo.md)

Optional specific failure information

---

### status

> **status**: [`PKIStatus`](../type-aliases/PKIStatus.md)

The status code indicating success or failure

---

### statusString?

> `optional` **statusString**: [`PKIFreeText`](PKIFreeText.md)

Optional human-readable status description

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

### getStatusDescription()

> **getStatusDescription**(): `string`

Get a human-readable status description

#### Returns

`string`

---

### isSuccess()

> **isSuccess**(): `boolean`

Check if the status indicates success

#### Returns

`boolean`

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

Converts the PKIStatusInfo to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

ASN.1 SEQUENCE containing status and optional fields

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`

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

> `static` **fromAsn1**(`asn1`): `PKIStatusInfo`

Creates a PKIStatusInfo from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure to parse

#### Returns

`PKIStatusInfo`

The parsed PKIStatusInfo object

#### Throws

Asn1ParseError if the ASN.1 structure is invalid
