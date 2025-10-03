[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs12/SafeBag](../README.md) / SafeBag

# Class: SafeBag

Represents a SafeBag structure in a PKCS#12 file.

A SafeBag is a container for different types of objects stored in PKCS#12
files, such as certificates, private keys, and CRLs. Each bag has a specific
type (bagId) that determines how to interpret the bag's content (bagValue).
Optional attributes can provide additional metadata like friendly names.

## Asn

```asn
SafeBag ::= SEQUENCE {
  bagId         BAG-TYPE,
  bagValue      [0] EXPLICIT ANY DEFINED BY bagId,
  bagAttributes SET OF PKCS12Attribute OPTIONAL
}
```

## Example

```typescript
// Create a certificate bag
const certBag = new SafeBag({
    bagId: OIDs.certBag,
    bagValue: new CertBag({
        certId: OIDs.x509Certificate,
        certValue: certificate.toDer(),
    }),
    bagAttributes: [
        new Attribute({
            type: OIDs.friendlyName,
            values: ['My Certificate'],
        }),
    ],
})

// Create a private key bag
const keyBag = new SafeBag({
    bagId: OIDs.pkcs8ShroudedKeyBag,
    bagValue: encryptedPrivateKeyInfo,
})

// Extract content based on bag type
if (safeBag.bagId.is(OIDs.certBag)) {
    const certBag = CertBag.fromAsn1(safeBag.bagValue.toAsn1())
    const certificate = certBag.extractCertificate()
}
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`SafeBag`\>

## Constructors

### Constructor

> **new SafeBag**(`options`): `SafeBag`

Creates a new SafeBag instance.

#### Parameters

##### options

Configuration object

###### bagAttributes?

[`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

Optional attributes for the bag

###### bagId

[`ObjectIdentifierString`](../../../core/PkiBase/type-aliases/ObjectIdentifierString.md)

Object identifier specifying the bag type

###### bagValue

[`Asn1Any`](../../../core/PkiBase/type-aliases/Asn1Any.md)

The bag content data

#### Returns

`SafeBag`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### bagAttributes?

> `optional` **bagAttributes**: [`Attribute`](../../../x509/Attribute/classes/Attribute.md)[]

Optional attributes providing metadata (e.g., friendly names, local key ID).

---

### bagId

> **bagId**: [`ObjectIdentifier`](../../../asn1/ObjectIdentifier/classes/ObjectIdentifier.md)

Object identifier specifying the type of bag content.
Common types include certBag, pkcs8ShroudedKeyBag, and keyBag.

---

### bagValue

> **bagValue**: [`Any`](../../../asn1/Any/classes/Any.md)

The bag content, format determined by the bagId.

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`pemHeader`](../../../core/PkiBase/classes/PkiBase.md#pemheader)

---

### pkiType

#### Get Signature

> **get** **pkiType**(): `string`

Gets the PKI type name for this object (typically the class name).
Used for PEM headers and debugging output.

##### Returns

`string`

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`pkiType`](../../../core/PkiBase/classes/PkiBase.md#pkitype)

## Methods

### equals()

> **equals**(`other`): `boolean`

Compares this PKI object with another for equality.
Two objects are considered equal if their DER encodings are identical.

#### Parameters

##### other

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`any`\>

The other PKI object to compare with

#### Returns

`boolean`

true if the objects are equal, false otherwise

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`equals`](../../../core/PkiBase/classes/PkiBase.md#equals)

---

### getAs()

> **getAs**\<`T`\>(`parseable`): `T`

#### Type Parameters

##### T

`T`

#### Parameters

##### parseable

[`ParseableAsn1`](../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

#### Returns

`T`

---

### is()

> **is**(`type`): `boolean`

#### Parameters

##### type

`"KEY_BAG"` | `"PKCS8_SHROUDED_KEY_BAG"` | `"CERT_BAG"` | `"CRL_BAG"` | `"SECRET_BAG"` | `"SAFE_CONTENTS_BAG"`

#### Returns

`boolean`

---

### isOid()

> **isOid**(`oid`): `boolean`

#### Parameters

##### oid

`string`

#### Returns

`boolean`

---

### parseAs()

> **parseAs**\<`T`\>(`type`): `T`

Parses this object as a different PKI type.
Useful for converting between related PKI structures.

#### Type Parameters

##### T

`T`

The target type to parse as

#### Parameters

##### type

[`ParseableAsn1`](../../../core/PkiBase/type-aliases/ParseableAsn1.md)\<`T`\>

The target type constructor with parsing capabilities

#### Returns

`T`

A new instance of the target type

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`parseAs`](../../../core/PkiBase/classes/PkiBase.md#parseas)

---

### toAsn1()

> **toAsn1**(): [`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

Converts this SafeBag to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 SEQUENCE structure

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`\<`ArrayBuffer`\>

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`\<`ArrayBuffer`\>

The DER-encoded bytes of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toDer`](../../../core/PkiBase/classes/PkiBase.md#toder)

---

### toHumanString()

> **toHumanString**(): `string`

Returns a human-readable string representation of this object.
By default, returns the same as toString(), but subclasses can override
for more user-friendly output.

#### Returns

`string`

A human-readable string representation

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toHumanString`](../../../core/PkiBase/classes/PkiBase.md#tohumanstring)

---

### toJSON()

> **toJSON**(): [`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

Converts this object to a JSON representation.

#### Returns

[`ToJson`](../../../core/PkiBase/type-aliases/ToJson.md)\<`T`\>

A JSON-serializable representation of this object

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toJSON`](../../../core/PkiBase/classes/PkiBase.md#tojson)

---

### toPem()

> **toPem**(): `string`

Converts this PKI object to PEM (Privacy-Enhanced Mail) format.

#### Returns

`string`

A PEM-encoded string with appropriate headers

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toPem`](../../../core/PkiBase/classes/PkiBase.md#topem)

---

### toString()

> **toString**(): `string`

Returns a string representation of this PKI object.
Includes the type name and ASN.1 structure.

#### Returns

`string`

A string representation for debugging

#### Inherited from

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toString`](../../../core/PkiBase/classes/PkiBase.md#tostring)

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `SafeBag`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`SafeBag`

---

### fromDer()

> `static` **fromDer**(`der`): `SafeBag`

#### Parameters

##### der

`Uint8Array`\<`ArrayBuffer`\>

#### Returns

`SafeBag`
