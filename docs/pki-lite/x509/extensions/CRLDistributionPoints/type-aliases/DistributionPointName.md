[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [x509/extensions/CRLDistributionPoints](../README.md) / DistributionPointName

# Type Alias: DistributionPointName

> **DistributionPointName** = [`GeneralNames`](../../../GeneralName/classes/GeneralNames.md) \| [`RelativeDistinguishedName`](../../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md)

Represents X.509 DistributionPointName

## Asn

```asn
DistributionPointName ::= CHOICE {
     fullName                [0]     GeneralNames,
     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName
}
```
