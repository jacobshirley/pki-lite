[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [ocsp/ResponderID](../README.md) / ResponderID

# Type Alias: ResponderID

> **ResponderID** = [`Name`](../../../x509/Name/type-aliases/Name.md) \| [`KeyHash`](KeyHash.md)

Represents the SHA-1 hash of the responder's key.

## Asn

```asn
ResponderID ::= CHOICE {
    byName              [1] Name,
    byKey               [2] KeyHash
}
```
