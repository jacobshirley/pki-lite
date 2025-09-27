[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [revocation/RevocationInfoChoice](../README.md) / RevocationInfoChoice

# Type Alias: RevocationInfoChoice

> **RevocationInfoChoice** = [`CertificateList`](../../../x509/CertificateList/classes/CertificateList.md) \| [`OtherRevocationInfoFormat`](../../OtherRevocationInfoFormat/classes/OtherRevocationInfoFormat.md)

Represents a single revocation information choice.

## Asn

```asn
RevocationInfoChoice ::= CHOICE {
     crl CertificateList,
     other [1] IMPLICIT OtherRevocationInfoFormat
}

OtherRevocationInfoFormat ::= SEQUENCE {
     otherRevInfoFormat OBJECT IDENTIFIER,
     otherRevInfo ANY DEFINED BY otherRevInfoFormat
}
```
