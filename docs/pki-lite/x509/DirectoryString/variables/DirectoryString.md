[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [x509/DirectoryString](../README.md) / DirectoryString

# Variable: DirectoryString

> **DirectoryString**: `object`

## Type Declaration

### bmpString

> **bmpString**: _typeof_ [`BMPString`](../../../asn1/BMPString/classes/BMPString.md) = `BMPString`

### printableString

> **printableString**: _typeof_ [`PrintableString`](../../../asn1/PrintableString/classes/PrintableString.md) = `PrintableString`

### teletexString

> **teletexString**: _typeof_ [`TeletexString`](../../../asn1/TeletexString/classes/TeletexString.md) = `TeletexString`

### universalString

> **universalString**: _typeof_ [`UniversalString`](../../../asn1/UniversalString/classes/UniversalString.md) = `UniversalString`

### utf8String

> **utf8String**: _typeof_ [`UTF8String`](../../../asn1/UTF8String/classes/UTF8String.md) = `UTF8String`

### fromAsn1()

> **fromAsn1**(`asn1`): [`UTF8String`](../../../asn1/UTF8String/classes/UTF8String.md) \| [`BMPString`](../../../asn1/BMPString/classes/BMPString.md) \| [`PrintableString`](../../../asn1/PrintableString/classes/PrintableString.md) \| [`TeletexString`](../../../asn1/TeletexString/classes/TeletexString.md) \| [`UniversalString`](../../../asn1/UniversalString/classes/UniversalString.md)

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

[`UTF8String`](../../../asn1/UTF8String/classes/UTF8String.md) \| [`BMPString`](../../../asn1/BMPString/classes/BMPString.md) \| [`PrintableString`](../../../asn1/PrintableString/classes/PrintableString.md) \| [`TeletexString`](../../../asn1/TeletexString/classes/TeletexString.md) \| [`UniversalString`](../../../asn1/UniversalString/classes/UniversalString.md)

### toAsn1()

> **toAsn1**(`value`): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Parameters

##### value

[`DirectoryString`](../type-aliases/DirectoryString.md)

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)
