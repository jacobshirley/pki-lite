[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / CertificateValidator

# Class: CertificateValidator

A comprehensive certificate validator that checks certificate validity,
expiration, and revocation status using CRLs and OCSP responses.

This class provides methods to validate X.509 certificates against
various criteria including:

- Certificate expiration dates
- Revocation status via Certificate Revocation Lists (CRLs)
- Revocation status via Online Certificate Status Protocol (OCSP)
- Certificate chain validation (when issuer certificates are provided)

## Example

```typescript
const validator = new CertificateValidator()

// Basic validation
const result = await validator.validate(certificate)

// Validation with revocation checking
const result = await validator.validate(
    certificate,
    {
        checkCRL: true,
        checkOCSP: true,
    },
    {
        crls: [crl1, crl2],
        ocspResponses: [ocspResponse],
    },
)
```

## Constructors

### Constructor

> **new CertificateValidator**(): `CertificateValidator`

#### Returns

`CertificateValidator`

## Methods

### buildCertificateChain()

> **buildCertificateChain**(`certificate`, `options`): `Promise`\<[`CertificateChain`](../interfaces/CertificateChain.md)\>

Builds a certificate chain from the end-entity certificate to a trusted root.

#### Parameters

##### certificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

##### options

[`CertificateValidationOptions`](../interfaces/CertificateValidationOptions.md)

#### Returns

`Promise`\<[`CertificateChain`](../interfaces/CertificateChain.md)\>

---

### validate()

> **validate**(`certificate`, `options`, `revocationData?`): `Promise`\<[`CertificateValidationResult`](../interfaces/CertificateValidationResult.md)\>

Validates a certificate against various criteria.

#### Parameters

##### certificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

The certificate to validate

##### options

[`CertificateValidationOptions`](../interfaces/CertificateValidationOptions.md) = `{}`

Validation options

##### revocationData?

Optional revocation data (CRLs and OCSP responses)

###### crls?

[`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md)[]

###### issuerCertificate?

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

###### ocspResponses?

[`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)[]

#### Returns

`Promise`\<[`CertificateValidationResult`](../interfaces/CertificateValidationResult.md)\>

Promise resolving to validation result

---

### validateChain()

> **validateChain**(`chain`, `options`, `revocationData?`): `Promise`\<[`CertificateValidationResult`](../interfaces/CertificateValidationResult.md)\>

Validates a complete certificate chain.

#### Parameters

##### chain

[`CertificateChain`](../interfaces/CertificateChain.md)

##### options

[`CertificateValidationOptions`](../interfaces/CertificateValidationOptions.md)

##### revocationData?

###### crls?

[`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md)[]

###### issuerCertificate?

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

###### ocspResponses?

[`OCSPResponse`](../../../ocsp/OCSPResponse/classes/OCSPResponse.md)[]

#### Returns

`Promise`\<[`CertificateValidationResult`](../interfaces/CertificateValidationResult.md)\>
