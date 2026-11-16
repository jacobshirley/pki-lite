[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/Certificate](../README.md) / Certificate

# Class: Certificate

Represents an X.509 certificate.

An X.509 certificate is a digital certificate that binds a public key to an identity.
It contains information about the certificate holder (subject), the issuer, validity
period, extensions, and a digital signature from the issuer. This class provides
comprehensive support for parsing, validating, and working with X.509 certificates.

## Asn

```asn
Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signatureValue       BIT STRING
}
```

## Example

```typescript
// Load certificate from PEM
const pem = '-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----'
const cert = Certificate.fromPem(pem)

// Access certificate information
console.log('Subject:', cert.tbsCertificate.subject.commonName)
console.log('Issuer:', cert.tbsCertificate.issuer.commonName)
console.log('Valid from:', cert.tbsCertificate.validity.notBefore)
console.log('Valid to:', cert.tbsCertificate.validity.notAfter)

// Create self-signed certificate
const selfSigned = await Certificate.createSelfSigned({
    subject: 'CN=Test Certificate, O=My Organization, C=US',
    validity: {
        notBefore: new Date('2023-01-01'),
        notAfter: new Date('2024-01-01'),
    },
    privateKeyInfo: privateKey,
    subjectPublicKeyInfo: publicKey,
})

// Validate certificate
const validationResult = await cert.validate({
    trustedCertificates: [caCert],
    checkRevocation: true,
})
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`Certificate`\>

## Constructors

### Constructor

> **new Certificate**(`options`): `Certificate`

Creates a new Certificate instance.

#### Parameters

##### options

Configuration object

###### signatureAlgorithm

[`AlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/AlgorithmIdentifier.md)

The signature algorithm

###### signatureValue

`Uint8Array`\<`ArrayBuffer`\> \| [`BitString`](../../../asn1/BitString/classes/BitString.md)

The signature bits

###### tbsCertificate

[`TBSCertificate`](../../TBSCertificate/classes/TBSCertificate.md)

The TBSCertificate structure

#### Returns

`Certificate`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### signatureAlgorithm

> **signatureAlgorithm**: [`SignatureAlgorithmIdentifier`](../../../algorithms/AlgorithmIdentifier/classes/SignatureAlgorithmIdentifier.md)

Algorithm used to sign this certificate.

---

### signatureValue

> **signatureValue**: [`BitString`](../../../asn1/BitString/classes/BitString.md)

The digital signature value from the issuer.

---

### tbsCertificate

> **tbsCertificate**: [`TBSCertificate`](../../TBSCertificate/classes/TBSCertificate.md)

The "to be signed" certificate containing most certificate data.

---

### TBSCertificate

> `static` **TBSCertificate**: _typeof_ [`TBSCertificate`](../../TBSCertificate/classes/TBSCertificate.md)

Reference to TBSCertificate class for easy access.

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

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

### allowsExtendedKeyUsage()

> **allowsExtendedKeyUsage**(`purpose`): `boolean`

Whether the certificate may be used for an extended key usage `purpose` (by common
name, e.g. `serverAuth`, or OID): it has no extendedKeyUsage extension (no limit),
or the extension lists the purpose or anyExtendedKeyUsage (RFC 5280 4.2.1.12).

#### Parameters

##### purpose

`string`

#### Returns

`boolean`

#### Example

```typescript
serverCert.allowsExtendedKeyUsage('serverAuth')
```

---

### allowsKeyUsage()

> **allowsKeyUsage**(`usage`): `boolean`

Whether the certificate's key may be used for `usage`: its keyUsage extension sets
that bit, or it has no keyUsage extension (which places no limit; RFC 5280 4.2.1.3).

#### Parameters

##### usage

keyof [`KeyUsageOptions`](../../extensions/KeyUsage/interfaces/KeyUsageOptions.md)

#### Returns

`boolean`

#### Example

```typescript
ca.allowsKeyUsage('cRLSign')
```

---

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

### getCommonName()

> **getCommonName**(): `undefined` \| `string`

Returns the Common Name (CN) from the certificate's subject, or undefined if not present.

#### Returns

`undefined` \| `string`

---

### getCrlDistributionPoints()

> **getCrlDistributionPoints**(): [`DistributionPoint`](../../extensions/CRLDistributionPoints/classes/DistributionPoint.md)[]

The certificate's CRL distribution points (none if it has no such extension).

#### Returns

[`DistributionPoint`](../../extensions/CRLDistributionPoints/classes/DistributionPoint.md)[]

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

### getExtensionsByName()

> **getExtensionsByName**(`name`): [`Extension`](../../Extension/classes/Extension.md)[]

#### Parameters

##### name

`"SUBJECT_KEY_IDENTIFIER"` | `"KEY_USAGE"` | `"SUBJECT_ALT_NAME"` | `"BASIC_CONSTRAINTS"` | `"CRL_NUMBER"` | `"NAME_CONSTRAINTS"` | `"CRL_DISTRIBUTION_POINTS"` | `"CERTIFICATE_POLICIES"` | `"ANY_POLICY"` | `"POLICY_MAPPINGS"` | `"POLICY_CONSTRAINTS"` | `"INHIBIT_ANY_POLICY"` | `"AUTHORITY_KEY_IDENTIFIER"` | `"EXTENDED_KEY_USAGE"` | `"AUTHORITY_INFO_ACCESS"` | `"CRL_REASON_CODE"` | `"DELTA_CRL_INDICATOR"` | `"ISSUING_DISTRIBUTION_POINT"` | `"CERTIFICATE_ISSUER"` | `"FRESHEST_CRL"` | `"ISSUER_ALT_NAME"` | `"INVALIDITY_DATE"` | `"HOLD_INSTRUCTION_CODE"`

#### Returns

[`Extension`](../../Extension/classes/Extension.md)[]

---

### getExtensionsByOid()

> **getExtensionsByOid**(`oid`): [`Extension`](../../Extension/classes/Extension.md)[]

#### Parameters

##### oid

`string`

#### Returns

[`Extension`](../../Extension/classes/Extension.md)[]

---

### getHash()

> **getHash**(`algorithm`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

#### Parameters

##### algorithm

[`HashAlgorithm`](../../../core/crypto/types/type-aliases/HashAlgorithm.md) = `'SHA-1'`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

---

### getIssuerSerial()

> **getIssuerSerial**(): [`IssuerSerial`](../../IssuerSerial/classes/IssuerSerial.md)

#### Returns

[`IssuerSerial`](../../IssuerSerial/classes/IssuerSerial.md)

---

### getSubjectAltNames()

> **getSubjectAltNames**(): [`SubjectAltName`](../../extensions/SubjectAltName/classes/SubjectAltName.md)[]

Returns all Subject Alternative Names from the certificate's extensions.

#### Returns

[`SubjectAltName`](../../extensions/SubjectAltName/classes/SubjectAltName.md)[]

---

### getSubjectAltNamesAsStrings()

> **getSubjectAltNamesAsStrings**(): `string`[]

Returns all Subject Alternative Names as strings (e.g. DNS names, email addresses).
This is a convenience method that extracts the string representation of each SAN entry.

#### Returns

`string`[]

An array of strings representing the Subject Alternative Names.

---

### getSubjectPublicKeyInfo()

> **getSubjectPublicKeyInfo**(): [`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

#### Returns

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

---

### isCA()

> **isCA**(): `boolean`

Whether this is a CA certificate: it has a basicConstraints extension with cA set
(RFC 5280 4.2.1.9).

#### Returns

`boolean`

---

### isIssuedBy()

> **isIssuedBy**(`issuer`): `Promise`\<`boolean`\>

#### Parameters

##### issuer

`Certificate`

#### Returns

`Promise`\<`boolean`\>

---

### isSelfSigned()

> **isSelfSigned**(): `Promise`\<`boolean`\>

#### Returns

`Promise`\<`boolean`\>

---

### matchesHostname()

> **matchesHostname**(`hostname`): `boolean`

Whether the certificate is valid for `hostname`, a DNS name or an IP address, as
RFC 9525 (TLS server identity) describes:

- an IP address matches an iPAddress subjectAltName with the same bytes
- a DNS name matches a dNSName subjectAltName ignoring case and a trailing dot, with
  internationalised names compared as A-labels (punycode); a `*` wildcard matches
  exactly one label, only as the whole leftmost label of a name with at least two
  more labels (`*.example.com`, not `*.com` or `f*.example.com`)

The subject's common name is not used, even without a subjectAltName.

#### Parameters

##### hostname

`string`

#### Returns

`boolean`

#### Example

```typescript
cert.matchesHostname('www.example.com')
cert.matchesHostname('192.0.2.1')
```

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

### requestCrl()

> **requestCrl**(`options?`): `Promise`\<`undefined` \| [`CertificateList`](../../CertificateList/classes/CertificateList.md)\>

#### Parameters

##### options?

###### crlDistributionPointUrls?

`string`[]

#### Returns

`Promise`\<`undefined` \| [`CertificateList`](../../CertificateList/classes/CertificateList.md)\>

---

### requestIssuerCertificate()

> **requestIssuerCertificate**(`options?`): `Promise`\<`undefined` \| `Certificate`\>

Downloads the certificate's issuer from the caIssuers URLs of its
authorityInfoAccess extension (and any given), trying each in turn. Only http: and
https: URLs are followed; the URLs come from the certificate, so this is a request
to wherever its issuer says.

#### Parameters

##### options?

###### issuerCertificateUrls?

`string`[]

More URLs to try, before the certificate's own

###### timeout?

`number`

How long to wait for each URL, in milliseconds (default
10,000)

#### Returns

`Promise`\<`undefined` \| `Certificate`\>

The issuer certificate, or undefined if none could be fetched

---

### requestOcsp()

> **requestOcsp**(`options?`): `Promise`\<`undefined` \| [`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)\>

#### Parameters

##### options?

###### issuerCertificate?

`Certificate`

###### issuerCertificateUrls?

`string`[]

###### ocspResponderUrls?

`string`[]

#### Returns

`Promise`\<`undefined` \| [`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)\>

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts the certificate to an ASN.1 structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

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

### validate()

> **validate**(`options?`): `Promise`\<[`CertificateValidationResult`](../../../core/CertificateValidator/interfaces/CertificateValidationResult.md)\>

#### Parameters

##### options?

[`CertificateValidationOptions`](../../../core/CertificateValidator/interfaces/CertificateValidationOptions.md)

#### Returns

`Promise`\<[`CertificateValidationResult`](../../../core/CertificateValidator/interfaces/CertificateValidationResult.md)\>

---

### builder()

> `static` **builder**(): [`CertificateBuilder`](../../../core/builders/CertificateBuilder/classes/CertificateBuilder.md)

Creates a new CertificateBuilder for constructing certificates.

#### Returns

[`CertificateBuilder`](../../../core/builders/CertificateBuilder/classes/CertificateBuilder.md)

A new CertificateBuilder instance

#### Example

```typescript
const cert = await Certificate.builder()
    .setSubject('CN=Example')
    .setPublicKey(publicKey)
    .setPrivateKey(privateKey)
    .setValidityDays(365)
    .selfSign()
```

---

### createCertificate()

> `static` **createCertificate**(`options`): `Promise`\<`Certificate`\>

#### Parameters

##### options

###### algorithm?

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

###### extensions?

[`Extension`](../../Extension/classes/Extension.md)[]

###### issuer

`Certificate`

###### privateKeyInfo

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

###### serialNumber?

`Uint8Array`\<`ArrayBuffer`\>

###### subject

`string` \| [`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

###### subjectPublicKeyInfo

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

###### validity

\{ `notAfter`: `Date`; `notBefore`: `Date`; \}

###### validity.notAfter

`Date`

###### validity.notBefore

`Date`

#### Returns

`Promise`\<`Certificate`\>

---

### createSelfSigned()

> `static` **createSelfSigned**(`options`): `Promise`\<`Certificate`\>

#### Parameters

##### options

###### algorithm?

[`AsymmetricEncryptionAlgorithmParams`](../../../core/crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

###### extensions?

[`Extension`](../../Extension/classes/Extension.md)[]

###### privateKeyInfo

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)

###### subject

`string` \| [`RDNSequence`](../../RDNSequence/classes/RDNSequence.md)

###### subjectPublicKeyInfo

[`SubjectPublicKeyInfo`](../../../keys/SubjectPublicKeyInfo/classes/SubjectPublicKeyInfo.md)

###### validity

\{ `notAfter`: `Date`; `notBefore`: `Date`; \}

###### validity.notAfter

`Date`

###### validity.notBefore

`Date`

#### Returns

`Promise`\<`Certificate`\>

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `Certificate`

Creates a Certificate from an ASN.1 structure.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`Certificate`

The Certificate

---

### fromDer()

> `static` **fromDer**(`der`): `Certificate`

#### Parameters

##### der

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

`Certificate`

---

### fromPem()

> `static` **fromPem**(`pem`): `Certificate`

#### Parameters

##### pem

`string`

#### Returns

`Certificate`
