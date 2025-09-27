[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [pkcs7/recipients/KeyTransRecipientInfo](../README.md) / RecipientIdentifier

# Type Alias: RecipientIdentifier

> **RecipientIdentifier** = [`IssuerAndSerialNumber`](../../../IssuerAndSerialNumber/classes/IssuerAndSerialNumber.md) \| [`SubjectKeyIdentifier`](../../../../keys/SubjectKeyIdentifier/classes/SubjectKeyIdentifier.md)

Represents the identifier of a recipient in a KeyTransRecipientInfo structure.

## Asn

```asn
RecipientIdentifier ::= CHOICE {
  issuerAndSerialNumber IssuerAndSerialNumber,
  subjectKeyIdentifier [0] SubjectKeyIdentifier
}
```
