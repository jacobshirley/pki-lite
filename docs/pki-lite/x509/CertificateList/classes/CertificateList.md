[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/CertificateList](../README.md) / CertificateList

# Class: CertificateList

X.509 Certificate Revocation List (CRL) implementation.

A CRL is a time-stamped list identifying revoked certificates that is signed by a CA.
CRLs are used to check if a certificate has been revoked before relying on it.
Each CRL has a validity period and contains information about when the next update
will be available.

## Asn

CertificateList ::= SEQUENCE {
tbsCertList TBSCertList,
signatureAlgorithm AlgorithmIdentifier,
signatureValue BIT STRING }

## Example

```typescript
// Create an empty CRL
const crl = await CertificateList.createEmpty({
    issuer: caName,
    privateKey: caPrivateKey,
    signatureAlgorithmParams: {
        type: 'RSASSA_PKCS1_v1_5',
        params: { hash: 'SHA-256' },
    },
})

// Load CRL from PEM
const crlFromPem = CertificateList.fromPem(pemString)

// Fetch CRL from URL
const crlFromUrl = await CertificateList.fetch('http://example.com/ca.crl')

// Check if certificate is revoked
const isRevoked = crl.tbsCertList.isRevoked(
    certificate.tbsCertificate.serialNumber,
)
```

## See

RFC 5280 Section 5 - CRL and CRL Extensions Profile

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`CertificateList`\>

## Constructors

### Constructor

> **new CertificateList**(`options`): `CertificateList`

Creates a new CertificateList instance.

#### Parameters

##### options

Configuration object

###### signatureAlgorithm

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The signature algorithm

###### signatureValue

`Uint8Array`\<`ArrayBufferLike`\> \| [`BitString`](../../../asn1/BitString/classes/BitString.md)

The signature bytes or BitString

###### tbsCertList

[`TBSCertList`](../../TBSCertList/classes/TBSCertList.md)

The TBS certificate list

#### Returns

`CertificateList`

#### Example

```typescript
const crl = new CertificateList({
    tbsCertList,
    signatureAlgorithm,
    signatureValue: signatureBytes,
})
```

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### signatureAlgorithm

> **signatureAlgorithm**: [`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

Algorithm used to sign the CRL

---

### signatureValue

> **signatureValue**: [`BitString`](../../../asn1/BitString/classes/BitString.md)

Digital signature over the TBS CRL

---

### tbsCertList

> **tbsCertList**: [`TBSCertList`](../../TBSCertList/classes/TBSCertList.md)

The TBS (To Be Signed) portion of the CRL containing the revocation list

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header for CRL encoding.

##### Returns

`string`

The PEM header string

#### Overrides

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

Converts the CRL to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

ASN.1 structure representing the CRL

#### Example

```typescript
const asn1 = crl.toAsn1()
const der = asn1.toBER(false) // Convert to DER encoding
```

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

### createEmpty()

> `static` **createEmpty**(`options`): `Promise`\<`CertificateList`\>

Creates an empty CRL with no revoked certificates.

This method is useful for initializing a new CRL or for testing purposes.
The created CRL will have a validity period of 30 days by default.

#### Parameters

##### options

Configuration for the empty CRL

###### issuer

[`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

The name of the CA issuing the CRL

###### privateKey

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

The CA's private key for signing

###### signatureAlgorithmParams?

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Optional signature algorithm, defaults to RSA-SHA256

#### Returns

`Promise`\<`CertificateList`\>

Promise resolving to the created empty CRL

#### Example

```typescript
const emptyCrl = await CertificateList.createEmpty({
    issuer: new Name({ commonName: 'Test CA' }),
    privateKey: caPrivateKey,
    signatureAlgorithmParams: {
        type: 'RSASSA_PKCS1_v1_5',
        params: { hash: 'SHA-384' },
    },
})

// CRL is valid for 30 days from creation
console.log(emptyCrl.tbsCertList.thisUpdate) // Current time
console.log(emptyCrl.tbsCertList.nextUpdate) // 30 days later
```

---

### fetch()

> `static` **fetch**(`url`): `Promise`\<`CertificateList`\>

Fetches a CRL from a URL and parses it.

This is commonly used to retrieve CRLs from Certificate Distribution Points
specified in X.509 certificates.

#### Parameters

##### url

`string`

The URL to fetch the CRL from

#### Returns

`Promise`\<`CertificateList`\>

Promise resolving to the fetched and parsed CRL

#### Throws

Error if the HTTP request fails or CRL parsing fails

#### Example

```typescript
// Fetch CRL from a CA's distribution point
const crl = await CertificateList.fetch('http://crl.example.com/ca.crl')

// Check certificate status
const serialNumber = certificate.tbsCertificate.serialNumber
if (crl.tbsCertList.isRevoked(serialNumber)) {
    console.log('Certificate is revoked')
}
```

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `CertificateList`

Creates a CertificateList from an ASN.1 structure.

Parses the ASN.1 SEQUENCE structure and extracts the TBS certificate list,
signature algorithm, and signature value components.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure to parse

#### Returns

`CertificateList`

The parsed CertificateList object

#### Throws

Asn1ParseError if the ASN.1 structure is invalid

#### Example

```typescript
const asn1 = derToAsn1(crlBytes)
const crl = CertificateList.fromAsn1(asn1)
```

---

### fromDer()

> `static` **fromDer**(`der`): `CertificateList`

Creates a CertificateList from DER-encoded bytes.

#### Parameters

##### der

`Uint8Array`

The DER-encoded CRL bytes

#### Returns

`CertificateList`

The parsed CertificateList

#### Throws

Error if DER parsing fails

#### Example

```typescript
const crl = CertificateList.fromDer(crlBytes)
```

---

### fromPem()

> `static` **fromPem**(`pem`): `CertificateList`

Creates a CertificateList from PEM-encoded text.

#### Parameters

##### pem

`string`

The PEM-encoded CRL string

#### Returns

`CertificateList`

The parsed CertificateList

#### Throws

Error if PEM parsing fails

#### Example

```typescript
const pemCrl = `
-----BEGIN X509 CRL-----
MIIBzDCBtQIBATANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJVUzELMAkGA1UE
...
-----END X509 CRL-----`

const crl = CertificateList.fromPem(pemCrl)
```
