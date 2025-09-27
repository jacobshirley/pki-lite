[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [pkcs7/recipients/KeyTransRecipientInfo](../README.md) / RecipientIdentifier

# Variable: RecipientIdentifier

> **RecipientIdentifier**: `object`

## Type Declaration

### fromAsn1()

> **fromAsn1**: (`asn1`) => [`RecipientIdentifier`](../type-aliases/RecipientIdentifier.md)

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

[`RecipientIdentifier`](../type-aliases/RecipientIdentifier.md)

### IssuerAndSerialNumber

> **IssuerAndSerialNumber**: _typeof_ [`IssuerAndSerialNumber`](../../../IssuerAndSerialNumber/classes/IssuerAndSerialNumber.md)

### SubjectKeyIdentifier

> **SubjectKeyIdentifier**: _typeof_ [`SubjectKeyIdentifier`](../../../../keys/SubjectKeyIdentifier/classes/SubjectKeyIdentifier.md)

### toAsn1()

> **toAsn1**: (`value`) => [`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Parameters

##### value

[`RecipientIdentifier`](../type-aliases/RecipientIdentifier.md)

#### Returns

[`Asn1BaseBlock`](../../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)
