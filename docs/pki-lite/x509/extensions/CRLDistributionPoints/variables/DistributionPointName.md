[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [x509/extensions/CRLDistributionPoints](../README.md) / DistributionPointName

# Variable: DistributionPointName

> **DistributionPointName**: `object`

## Type Declaration

### fullName

> **fullName**: _typeof_ [`GeneralNames`](../../../GeneralName/classes/GeneralNames.md) = `GeneralNames`

### nameRelativeToCRLIssuer

> **nameRelativeToCRLIssuer**: _typeof_ [`RelativeDistinguishedName`](../../../RelativeDistinguishedName/classes/RelativeDistinguishedName.md) = `RelativeDistinguishedName`

### fromAsn1()

> **fromAsn1**(`asn1`): [`DistributionPointName`](../type-aliases/DistributionPointName.md)

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

[`DistributionPointName`](../type-aliases/DistributionPointName.md)

### toAsn1()

> **toAsn1**(`value`): [`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Parameters

##### value

[`DistributionPointName`](../type-aliases/DistributionPointName.md)

#### Returns

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)
