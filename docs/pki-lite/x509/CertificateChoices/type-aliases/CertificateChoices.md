[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/CertificateChoices](../README.md) / CertificateChoices

# Type Alias: CertificateChoices

> **CertificateChoices** = [`Certificate`](../../Certificate/classes/Certificate.md) \| [`ExtendedCertificate`](../../legacy/ExtendedCertificate/classes/ExtendedCertificate.md) \| [`AttributeCertificateV1`](../../attribute-certs/AttributeCertificateV1/classes/AttributeCertificateV1.md) \| [`AttributeCertificate`](../../attribute-certs/AttributeCertificate/classes/AttributeCertificate.md) \| [`OtherCertificateFormat`](../../legacy/OtherCertificateFormat/classes/OtherCertificateFormat.md)

Represents a certificate choice structure used in PKCS#7/CMS.

## Asn

```asn
CertificateChoices ::= CHOICE {
     certificate Certificate,
     extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
     v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
     v2AttrCert [2] IMPLICIT AttributeCertificate,
     other [3] IMPLICIT OtherCertificateFormat
}

AttributeCertificateV2 ::= AttributeCertificate

OtherCertificateFormat ::= SEQUENCE {
     otherCertFormat OBJECT IDENTIFIER,
     otherCert ANY DEFINED BY otherCertFormat
}
```
