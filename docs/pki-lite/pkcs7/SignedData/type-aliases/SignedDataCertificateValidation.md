[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/SignedData](../README.md) / SignedDataCertificateValidation

# Type Alias: SignedDataCertificateValidation

> **SignedDataCertificateValidation** = [`CertificateValidationOptions`](../../../core/CertificateValidator/interfaces/CertificateValidationOptions.md) & `object`

Validation of a SignedData signer's certificate (SignedData.verify): the options of
CertificateValidator, with the trust anchors required, since without them nothing ties
the signer to a root you trust.

## Type Declaration

### trustAnchors

> **trustAnchors**: [`TrustAnchor`](../../../core/CertificateValidator/interfaces/TrustAnchor.md)[]
