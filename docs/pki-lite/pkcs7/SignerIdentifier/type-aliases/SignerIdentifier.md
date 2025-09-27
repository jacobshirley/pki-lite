[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs7/SignerIdentifier](../README.md) / SignerIdentifier

# Type Alias: SignerIdentifier

> **SignerIdentifier** = [`IssuerAndSerialNumber`](../../IssuerAndSerialNumber/classes/IssuerAndSerialNumber.md) \| [`SubjectKeyIdentifier`](../../../keys/SubjectKeyIdentifier/classes/SubjectKeyIdentifier.md)

Represents a CMS SignerIdentifier structure as defined in RFC 5652.

## Asn

```asn
SignerIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier
}
```
