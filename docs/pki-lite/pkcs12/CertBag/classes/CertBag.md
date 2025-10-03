[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs12/CertBag](../README.md) / CertBag

# Class: CertBag

Represents a CertBag structure in a PKCS#12 file.

A CertBag is used to store certificates within PKCS#12 files. It specifies
the certificate type (certId) and contains the certificate data (certValue).
The most common certificate type is X.509 certificates, but other formats
can also be stored.

## Asn

```asn
CertBag ::= SEQUENCE {
  certId    BAG-TYPE,
  certValue [0] EXPLICIT ANY DEFINED BY certId
}
```

## Example

```typescript
// Create a certificate bag for an X.509 certificate
const certBag = new CertBag({
    certId: OIDs.x509Certificate,
    certValue: certificate.toDer(),
})

// Extract certificate from bag
if (certBag.certId.is(OIDs.x509Certificate)) {
    const certBytes = certBag.certValue.toAsn1().valueBlock.valueHex
    const certificate = Certificate.fromDer(new Uint8Array(certBytes))
}

// Create from existing certificate
const bagFromCert = CertBag.fromCertificate(certificate)
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`CertBag`\>

## Constructors

### Constructor

> **new CertBag**(`options`): `CertBag`

Creates a new CertBag instance.

#### Parameters

##### options

Configuration object

###### certId

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

Object identifier for the certificate type

###### certValue

[`Asn1Any`](../../../core/PkiBase/type-aliases/Asn1Any.md)

The certificate data

#### Returns

`CertBag`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### certId

> **certId**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Object identifier specifying the certificate type.
Common value is OIDs.x509Certificate for X.509 certificates.

---

### certValue

> **certValue**: [`Any`](../../../asn1/Any/classes/Any.md)

The certificate data, format determined by certId.

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

Converts this CertBag to its ASN.1 representation.

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

> `static` **fromAsn1**(`asn1`): `CertBag`

Creates a CertBag from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 SEQUENCE to parse

#### Returns

`CertBag`

A new CertBag instance

#### Throws

Asn1ParseError if the ASN.1 structure is invalid

---

### fromDer()

> `static` **fromDer**(`der`): `CertBag`

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

#### Returns

`CertBag`
