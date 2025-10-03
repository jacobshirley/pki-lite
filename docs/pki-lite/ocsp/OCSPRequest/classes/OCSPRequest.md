[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [ocsp/OCSPRequest](../README.md) / OCSPRequest

# Class: OCSPRequest

Represents an OCSP (Online Certificate Status Protocol) request.

An OCSP request is used to check the revocation status of X.509 certificates
in real-time. It can request the status of one or more certificates and
optionally include a signature to authenticate the requestor.

## Asn

```asn
OCSPRequest ::= SEQUENCE {
    tbsRequest              TBSRequest,
    optionalSignature   [0] EXPLICIT Signature OPTIONAL
}
```

## Example

```typescript
// Create OCSP request for a certificate
const request = await OCSPRequest.forCertificate({
    certificate: clientCert,
    issuerCertificate: caCert,
})

// Send to OCSP responder
const response = await fetch('http://ocsp.example.com', {
    method: 'POST',
    body: request.toDer(),
    headers: { 'Content-Type': 'application/ocsp-request' },
})

// Parse response
const ocspResponse = OCSPResponse.fromDer(
    new Uint8Array(await response.arrayBuffer()),
)
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`OCSPRequest`\>

## Constructors

### Constructor

> **new OCSPRequest**(`options`): `OCSPRequest`

Creates a new OCSPRequest instance.

#### Parameters

##### options

Configuration object

###### optionalSignature?

[`OCSPSignature`](../../OCSPSignature/classes/OCSPSignature.md)

Optional signature for authentication

###### tbsRequest

[`TBSRequest`](../../TBSRequest/classes/TBSRequest.md)

The TBSRequest structure

#### Returns

`OCSPRequest`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### optionalSignature?

> `optional` **optionalSignature**: [`OCSPSignature`](../../OCSPSignature/classes/OCSPSignature.md)

Optional signature to authenticate the requestor.

---

### tbsRequest

> **tbsRequest**: [`TBSRequest`](../../TBSRequest/classes/TBSRequest.md)

The "to be signed" request containing the certificate status queries.

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

> **request**(`options`): `Promise`\<[`OCSPResponse`](../../OCSPResponse/classes/OCSPResponse.md)\>

#### Parameters

##### options

###### url

`string`

#### Returns

`Promise`\<[`OCSPResponse`](../../OCSPResponse/classes/OCSPResponse.md)\>

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

### forCertificate()

> `static` **forCertificate**(`options`): `Promise`\<`OCSPRequest`\>

Creates an OCSP request for checking a specific certificate's status.

#### Parameters

##### options

Configuration object

###### certificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

The certificate to check

###### issuerCertificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

The issuer's certificate

#### Returns

`Promise`\<`OCSPRequest`\>

A new OCSPRequest instance

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `OCSPRequest`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`OCSPRequest`

---

### fromDer()

> `static` **fromDer**(`der`): `OCSPRequest`

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

#### Returns

`OCSPRequest`
