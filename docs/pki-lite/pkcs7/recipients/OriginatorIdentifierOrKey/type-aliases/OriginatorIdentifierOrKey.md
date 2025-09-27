[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [pkcs7/recipients/OriginatorIdentifierOrKey](../README.md) / OriginatorIdentifierOrKey

# Type Alias: OriginatorIdentifierOrKey

> **OriginatorIdentifierOrKey** = [`IssuerAndSerialNumber`](../../../IssuerAndSerialNumber/classes/IssuerAndSerialNumber.md) \| [`SubjectKeyIdentifier`](../../../../keys/SubjectKeyIdentifier/classes/SubjectKeyIdentifier.md) \| [`OriginatorPublicKey`](../../OriginatorPublicKey/classes/OriginatorPublicKey.md)

Represents an OriginatorIdentifierOrKey structure as defined in RFC 5652.

## Asn

```asn
OriginatorIdentifierOrKey ::= CHOICE {
  issuerAndSerialNumber IssuerAndSerialNumber,
  subjectKeyIdentifier [0] SubjectKeyIdentifier,
  originatorKey [1] OriginatorPublicKey }
```
