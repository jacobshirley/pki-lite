[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [ocsp/ResponderID](../README.md) / ResponderID

# Variable: ResponderID

> **ResponderID**: `object`

## Type Declaration

### byKey

> **byKey**: _typeof_ [`OctetString`](../../../asn1/OctetString/classes/OctetString.md) = `KeyHash`

### byName

> **byName**: `object` = `Name`

#### byName.RDNSequence

> **RDNSequence**: _typeof_ [`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

#### byName.fromAsn1()

> **fromAsn1**(`asn1`): [`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

##### Parameters

###### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

##### Returns

[`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

#### byName.parse()

> **parse**(`humanString`): [`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

##### Parameters

###### humanString

`string`

##### Returns

[`RDNSequence`](../../../x509/RDNSequence/classes/RDNSequence.md)

### fromAsn1()

> **fromAsn1**: (`asn1`) => [`ResponderID`](../type-aliases/ResponderID.md)

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

[`ResponderID`](../type-aliases/ResponderID.md)

### toAsn1()

> **toAsn1**: (`value`) => [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Parameters

##### value

[`ResponderID`](../type-aliases/ResponderID.md)

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)
