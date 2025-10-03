[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [timestamp/TimeStampReq](../README.md) / TimeStampReq

# Class: TimeStampReq

Time-Stamp Request structure for RFC 3161 Time-Stamp Protocol.

A TimeStampReq is sent to a Time Stamping Authority (TSA) to request a timestamp
for data. The request contains a hash of the data to be timestamped (MessageImprint)
along with optional parameters like policy requirements and nonce for replay protection.

## Asn

TimeStampReq ::= SEQUENCE {
version INTEGER { v1(1) },
messageImprint MessageImprint,
reqPolicy TSAPolicyId OPTIONAL,
nonce TSANonce OPTIONAL,
certReq BOOLEAN DEFAULT FALSE,
extensions [0] IMPLICIT Extensions OPTIONAL }

TSAPolicyId ::= OBJECT IDENTIFIER
TSANonce ::= INTEGER

## Example

```typescript
// Create a timestamp request for some data
const data = new TextEncoder().encode('Important document')
const algorithm = AlgorithmIdentifier.digestAlgorithm('SHA-256')

const messageImprint = new MessageImprint({
    hashAlgorithm: algorithm,
    hashedMessage: new Uint8Array(await algorithm.digest(data)),
})

const tsReq = new TimeStampReq({
    version: 1,
    messageImprint: messageImprint,
    reqPolicy: '1.3.6.1.4.1.123.456.1', // TSA policy OID
    nonce: crypto.getRandomValues(new Uint8Array(16)),
    certReq: true, // Request TSA certificate in response
})

// Send to TSA
const tsResp = await tsReq.request({
    url: 'http://timestamp.example.com/tsa',
    timeout: 30000,
})
```

## See

RFC 3161 Section 2.4.1 - TSAReq Structure

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`TimeStampReq`\>

## Constructors

### Constructor

> **new TimeStampReq**(`options`): `TimeStampReq`

Creates a new TimeStampReq instance.

#### Parameters

##### options

Configuration object for the timestamp request

###### certReq?

`boolean`

Whether to request the TSA certificate

###### extensions?

[`Extension`](../../../x509/Extension/classes/Extension.md)[]

Optional request extensions

###### messageImprint

[`MessageImprint`](../../MessageImprint/classes/MessageImprint.md)

Hash imprint of the data to timestamp

###### nonce?

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

Optional nonce for replay protection

###### reqPolicy?

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

Optional TSA policy OID

###### version?

`number`

Protocol version, defaults to 1

#### Returns

`TimeStampReq`

#### Example

```typescript
const request = new TimeStampReq({
    messageImprint: messageImprint,
    reqPolicy: '1.3.6.1.4.1.123.456.1',
    nonce: crypto.getRandomValues(new Uint8Array(8)),
    certReq: true,
})
```

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### certReq

> **certReq**: `boolean` = `false`

Whether to include the TSA certificate in the response

---

### extensions?

> `optional` **extensions**: [`Extension`](../../../x509/Extension/classes/Extension.md)[]

Optional extensions for additional functionality

---

### messageImprint

> **messageImprint**: [`MessageImprint`](../../MessageImprint/classes/MessageImprint.md)

Hash of the data to be timestamped

---

### nonce?

> `optional` **nonce**: `Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

Optional nonce for replay protection, should be unique per request

---

### reqPolicy?

> `optional` **reqPolicy**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Optional TSA policy identifier specifying how the timestamp should be created

---

### version

> **version**: `number`

Version of the TSA request format, currently always 1

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

### request()

> **request**(`options`): `Promise`\<[`TimeStampResp`](../../TimeStampResp/classes/TimeStampResp.md)\>

Sends the timestamp request to a Time Stamping Authority (TSA).

This method handles the HTTP protocol for communicating with RFC 3161
compliant TSA servers. It sends the request as application/timestamp-query
and expects an application/timestamp-reply response.

#### Parameters

##### options

Request configuration

###### otherRequestOptions?

`RequestInit`

Additional fetch options

###### password?

`string`

Optional basic auth password

###### timeout?

`number`

Optional request timeout in milliseconds

###### url

`string`

TSA server URL

###### username?

`string`

Optional basic auth username

#### Returns

`Promise`\<[`TimeStampResp`](../../TimeStampResp/classes/TimeStampResp.md)\>

Promise resolving to the timestamp response

#### Throws

Error if the HTTP request fails or TSA returns an error

#### Example

```typescript
// Simple request to public TSA
const response = await tsReq.request({
    url: 'http://timestamp.digicert.com',
})

// Authenticated request with timeout
const response = await tsReq.request({
    url: 'https://tsa.example.com/tsa',
    username: 'user',
    password: 'pass',
    timeout: 30000,
})

if (response.status.status === 0) {
    // Granted
    console.log('Timestamp obtained:', response.timeStampToken)
} else {
    console.error('Timestamp request failed:', response.status.failInfo)
}
```

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts the TimeStampReq to its ASN.1 representation.

Creates a SEQUENCE containing all the request fields in the proper order
according to RFC 3161 specification.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

ASN.1 structure representing the timestamp request

#### Example

```typescript
const asn1 = tsReq.toAsn1()
const der = asn1.toBER(false) // Convert to DER for transmission
```

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

### create()

> `static` **create**(`options`): `TimeStampReq`

Creates a TimeStampReq with the specified options.

Alternative constructor method that provides more explicit parameter naming.

#### Parameters

##### options

Request configuration

###### certReq?

`boolean`

###### extensions?

[`Extension`](../../../x509/Extension/classes/Extension.md)[]

###### messageImprint

[`MessageImprint`](../../MessageImprint/classes/MessageImprint.md)

###### nonce?

`Uint8Array<ArrayBuffer>`\<`ArrayBufferLike`\>

###### reqPolicy?

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

###### version?

`number`

#### Returns

`TimeStampReq`

A new TimeStampReq instance

#### Example

```typescript
const request = TimeStampReq.create({
    messageImprint: messageImprint,
    reqPolicy: '1.3.6.1.4.1.123.456.1',
    nonce: crypto.getRandomValues(new Uint8Array(16)),
    certReq: true,
})
```

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `TimeStampReq`

Creates a TimeStampReq from an ASN.1 structure.

Parses the ASN.1 SEQUENCE and extracts all optional and required fields
according to RFC 3161 specification.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure to parse

#### Returns

`TimeStampReq`

The parsed TimeStampReq object

#### Throws

Asn1ParseError if the ASN.1 structure is invalid

#### Example

```typescript
const asn1 = derToAsn1(requestBytes)
const request = TimeStampReq.fromAsn1(asn1)

console.log(request.version) // Should be 1
console.log(request.messageImprint.hashAlgorithm)
console.log(request.certReq) // Certificate requested
```

---

### fromDer()

> `static` **fromDer**(`der`): `TimeStampReq`

Creates a TimeStampReq from DER-encoded bytes.

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

The DER-encoded timestamp request bytes

#### Returns

`TimeStampReq`

The parsed TimeStampReq

#### Throws

Error if DER parsing fails

---

### fromMessageImprint()

> `static` **fromMessageImprint**(`messageImprint`): `TimeStampReq`

Creates a simple TimeStampReq from a MessageImprint.

Convenience method for creating a basic timestamp request with default settings.

#### Parameters

##### messageImprint

[`MessageImprint`](../../MessageImprint/classes/MessageImprint.md)

The message imprint to timestamp

#### Returns

`TimeStampReq`

A new TimeStampReq with version 1 and the given message imprint

#### Example

```typescript
const request = TimeStampReq.fromMessageImprint(messageImprint)
```
