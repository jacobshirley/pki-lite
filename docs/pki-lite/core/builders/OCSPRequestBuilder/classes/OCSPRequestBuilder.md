[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/OCSPRequestBuilder](../README.md) / OCSPRequestBuilder

# Class: OCSPRequestBuilder

Builder class for creating OCSP (Online Certificate Status Protocol) requests.

Provides a fluent API for constructing OCSP requests with one or more
certificate status queries.

## Example

```typescript
// Single certificate check
const request = await OCSPRequest.builder()
    .addCertificate({
        certificate: clientCert,
        issuerCertificate: caCert,
    })
    .build()

// Multiple certificates with custom hash algorithm
const request = await OCSPRequest.builder()
    .setHashAlgorithm('SHA-1')
    .addCertificate({ certificate: cert1, issuerCertificate: caCert })
    .addCertificate({ certificate: cert2, issuerCertificate: caCert })
    .build()

const response = await request.request({ url: 'http://ocsp.example.com' })
```

## Implements

- [`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md)\<[`OCSPRequest`](../../../../ocsp/OCSPRequest/classes/OCSPRequest.md)\>

## Constructors

### Constructor

> **new OCSPRequestBuilder**(): `OCSPRequestBuilder`

#### Returns

`OCSPRequestBuilder`

## Methods

### addCertificate()

> **addCertificate**(`options`): `this`

Adds a certificate to be checked against its issuer.
The issuer name and key hashes will be computed automatically.

#### Parameters

##### options

Certificate and its issuer

###### certificate

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

###### issuerCertificate

[`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

###### singleRequestExtensions?

[`Extension`](../../../../x509/Extension/classes/Extension.md)[]

#### Returns

`this`

This builder for chaining

---

### addExtension()

> **addExtension**(`extension`): `this`

Adds a request-level extension (e.g., nonce).

#### Parameters

##### extension

[`Extension`](../../../../x509/Extension/classes/Extension.md)

The extension to add

#### Returns

`this`

This builder for chaining

---

### addRequest()

> **addRequest**(`request`): `this`

Adds a pre-built Request entry.

#### Parameters

##### request

[`Request`](../../../../ocsp/Request/classes/Request.md)

The Request to add

#### Returns

`this`

This builder for chaining

---

### build()

> **build**(): `Promise`\<[`OCSPRequest`](../../../../ocsp/OCSPRequest/classes/OCSPRequest.md)\>

Builds the OCSP request, computing CertIDs for all pending certificates.

#### Returns

`Promise`\<[`OCSPRequest`](../../../../ocsp/OCSPRequest/classes/OCSPRequest.md)\>

Promise resolving to the OCSPRequest

#### Implementation of

[`AsyncBuilder`](../../types/interfaces/AsyncBuilder.md).[`build`](../../types/interfaces/AsyncBuilder.md#build)

---

### setHashAlgorithm()

> **setHashAlgorithm**(`hash`): `this`

Sets the hash algorithm used to compute issuer name and key hashes
in CertID. Defaults to 'SHA-256'.

Note: many OCSP responders only support SHA-1.

#### Parameters

##### hash

[`HashAlgorithm`](../../../crypto/types/type-aliases/HashAlgorithm.md)

The hash algorithm

#### Returns

`this`

This builder for chaining

---

### setRequestorName()

> **setRequestorName**(`name`): `this`

Sets the requestor's distinguished name (optional).

#### Parameters

##### name

Requestor name as string or Name object

`string` | [`RDNSequence`](../../../../x509/RDNSequence/classes/RDNSequence.md)

#### Returns

`this`

This builder for chaining

---

### setVersion()

> **setVersion**(`version`): `this`

Sets the protocol version. Defaults to 0 (v1).

#### Parameters

##### version

`number`

The protocol version

#### Returns

`this`

This builder for chaining
