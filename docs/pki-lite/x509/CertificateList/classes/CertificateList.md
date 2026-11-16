[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/CertificateList](../README.md) / CertificateList

# Class: CertificateList

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

`Uint8Array`\<`ArrayBuffer`\> \| [`BitString`](../../../asn1/BitString/classes/BitString.md)

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

### baseCrlNumber

#### Get Signature

> **get** **baseCrlNumber**(): `undefined` \| `bigint`

For a delta CRL, the number of the complete CRL it updates (deltaCRLIndicator).

##### Returns

`undefined` \| `bigint`

---

### crlNumber

#### Get Signature

> **get** **crlNumber**(): `undefined` \| `bigint`

The CRL number (cRLNumber extension), if present.

##### Returns

`undefined` \| `bigint`

---

### isDelta

#### Get Signature

> **get** **isDelta**(): `boolean`

Whether this is a delta CRL (it has a deltaCRLIndicator extension).

##### Returns

`boolean`

---

### issuingDistributionPoint

#### Get Signature

> **get** **issuingDistributionPoint**(): `undefined` \| [`IssuingDistributionPoint`](../../extensions/IssuingDistributionPoint/classes/IssuingDistributionPoint.md)

Which certificates and reasons the CRL covers (issuingDistributionPoint), if limited.

##### Returns

`undefined` \| [`IssuingDistributionPoint`](../../extensions/IssuingDistributionPoint/classes/IssuingDistributionPoint.md)

---

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

### getExtensionByName()

> **getExtensionByName**(`name`): `undefined` \| [`Extension`](../../Extension/classes/Extension.md)

#### Parameters

##### name

`"SUBJECT_KEY_IDENTIFIER"` | `"KEY_USAGE"` | `"SUBJECT_ALT_NAME"` | `"BASIC_CONSTRAINTS"` | `"CRL_NUMBER"` | `"NAME_CONSTRAINTS"` | `"CRL_DISTRIBUTION_POINTS"` | `"CERTIFICATE_POLICIES"` | `"ANY_POLICY"` | `"POLICY_MAPPINGS"` | `"POLICY_CONSTRAINTS"` | `"INHIBIT_ANY_POLICY"` | `"AUTHORITY_KEY_IDENTIFIER"` | `"EXTENDED_KEY_USAGE"` | `"AUTHORITY_INFO_ACCESS"` | `"CRL_REASON_CODE"` | `"DELTA_CRL_INDICATOR"` | `"ISSUING_DISTRIBUTION_POINT"` | `"CERTIFICATE_ISSUER"` | `"FRESHEST_CRL"` | `"ISSUER_ALT_NAME"` | `"INVALIDITY_DATE"` | `"HOLD_INSTRUCTION_CODE"`

#### Returns

`undefined` \| [`Extension`](../../Extension/classes/Extension.md)

---

### getExtensionByOid()

> **getExtensionByOid**(`oid`): `undefined` \| [`Extension`](../../Extension/classes/Extension.md)

#### Parameters

##### oid

`string`

#### Returns

`undefined` \| [`Extension`](../../Extension/classes/Extension.md)

---

### getRevokedEntry()

> **getRevokedEntry**(`certificate`): `undefined` \| [`RevokedCertificate`](../../RevokedCertificate/classes/RevokedCertificate.md)

The entry listing `certificate`, if this CRL has one: the same serial number, from
the certificate's issuer. On an indirect CRL, the issuer of each entry comes from
the certificateIssuer extensions (RFC 5280 5.3.3); otherwise it is the CRL issuer.

Does not check that the CRL is genuine or current: see [verify](#verify) and
[isCurrent](#iscurrent).

#### Parameters

##### certificate

[`Certificate`](../../Certificate/classes/Certificate.md)

#### Returns

`undefined` \| [`RevokedCertificate`](../../RevokedCertificate/classes/RevokedCertificate.md)

---

### isCurrent()

> **isCurrent**(`time`): `boolean`

Whether the CRL is current at `time`: issued (thisUpdate) at or before it, and not
yet due for replacement (nextUpdate). A CRL without nextUpdate is never current,
since its freshness cannot be established (RFC 5280 5.1.2.5).

#### Parameters

##### time

`Date` = `...`

The time to check at (default now)

#### Returns

`boolean`

---

### isRevoked()

> **isRevoked**(`certificate`): `boolean`

Whether this CRL lists `certificate` as revoked (or on hold). An entry with reason
removeFromCRL, which a delta CRL uses to lift a hold, does not count.

Does not check that the CRL is genuine or current: see [verify](#verify) and
[isCurrent](#iscurrent). To check revocation as part of path validation, use
CertificateValidator with `checkCRL`.

#### Parameters

##### certificate

[`Certificate`](../../Certificate/classes/Certificate.md)

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

### verify()

> **verify**(`issuer`): `Promise`\<`boolean`\>

Verifies that `issuer` signed this CRL: the CRL's issuer name matches the
certificate's subject (RFC 5280 7.1), the certificate's key may sign CRLs (keyUsage
cRLSign), and the signature verifies over the bytes that were signed.

This checks the CRL, not the issuer: whether the issuer's certificate is itself
trusted is up to certification path validation (CertificateValidator).

#### Parameters

##### issuer

[`Certificate`](../../Certificate/classes/Certificate.md)

The certificate of the CRL issuer

#### Returns

`Promise`\<`boolean`\>

Whether the CRL is signed by `issuer`

#### Throws

If the signature algorithm is not supported

#### Example

```typescript
const crl = CertificateList.fromPem(crlPem)
if (!(await crl.verify(caCertificate)))
    throw new Error('CRL not signed by the CA')
```

---

### builder()

> `static` **builder**(): [`CertificateListBuilder`](../../../core/builders/CertificateListBuilder/classes/CertificateListBuilder.md)

Creates a fluent builder for constructing CRLs.

#### Returns

[`CertificateListBuilder`](../../../core/builders/CertificateListBuilder/classes/CertificateListBuilder.md)

A new CertificateListBuilder instance

#### Example

```typescript
const crl = await CertificateList.builder()
    .setIssuer('CN=My CA')
    .setPrivateKey(caKey)
    .addRevokedCertificate({ serialNumber: 12345, revocationDate: new Date() })
    .build()
```

---

### createEmpty()

> `static` **createEmpty**(`options`): `Promise`\<`CertificateList`\>

#### Parameters

##### options

###### issuer

[`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

###### privateKey

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

###### signatureAlgorithmParams?

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

#### Returns

`Promise`\<`CertificateList`\>

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

`Uint8Array`\<`ArrayBuffer`\>

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
