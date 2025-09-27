[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [x509/attributes/SignaturePolicyIdentifier](../README.md) / SignaturePolicyIdentifier

# Type Alias: SignaturePolicyIdentifier

> **SignaturePolicyIdentifier** = [`SignaturePolicyId`](../classes/SignaturePolicyId.md) \| `null`

Represents a SignaturePolicyIdentifier attribute.

## Asn

```asn
SignaturePolicyIdentifier ::= CHOICE {
   signaturePolicyId          SignaturePolicyId,
   signaturePolicyImplied     SignaturePolicyImplied
                              -- not used in this version
}

SignaturePolicyImplied ::= NULL
```
