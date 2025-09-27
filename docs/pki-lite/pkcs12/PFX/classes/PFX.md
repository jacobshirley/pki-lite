[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [pkcs12/PFX](../README.md) / PFX

# Class: PFX

Represents a PFX structure in a PKCS#12 file.

PFX (Personal Information Exchange) is the main container format for PKCS#12
files. It can store private keys, certificates, and other cryptographic objects
in a password-protected format. PKCS#12 files are commonly used for importing
and exporting certificates and private keys between applications.

## Asn

```asn
PFX ::= SEQUENCE {
  version     INTEGER {v3(3)}(v3,...),
  authSafe    ContentInfo,
  macData     MacData OPTIONAL
}
```

## Example

```typescript
// Load PKCS#12 file from PEM
const p12Pem = '-----BEGIN PKCS12-----...-----END PKCS12-----'
const pfx = PFX.fromPem(p12Pem)

// Extract certificates and private keys
const items = await pfx.extractItems('password123')
const certificate = items.certificates[0]
const privateKey = items.privateKeys[0]

// Create new PKCS#12 file
const newPfx = await PFX.create({
    certificates: [clientCert, caCert],
    privateKeys: [privateKey],
    password: 'newPassword',
    friendlyName: 'My Certificate',
})

// Save as PEM
const pemData = newPfx.toPem()
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`PFX`\>

## Constructors

### Constructor

> **new PFX**(`options`): `PFX`

Creates a new PFX instance.

#### Parameters

##### options

Configuration object

###### authSafe

[`ContentInfo`](../../../pkcs7/ContentInfo/classes/ContentInfo.md)

The authenticated safe content

###### macData?

[`MacData`](../../MacData/classes/MacData.md)

Optional MAC data for integrity

###### version?

`number`

Version number (defaults to 3)

#### Returns

`PFX`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### authSafe

> **authSafe**: [`ContentInfo`](../../../pkcs7/ContentInfo/classes/ContentInfo.md)

The authenticated safe containing the encrypted content.

---

### macData?

> `optional` **macData**: [`MacData`](../../MacData/classes/MacData.md)

Optional MAC data for integrity verification.

---

### version

> **version**: `number`

Version number (typically 3 for PKCS#12 v1.0).

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

### pemHeaders

#### Get Signature

> **get** **pemHeaders**(): `string`

Gets the PEM header name for PKCS#12 files.

##### Returns

`string`

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

### extractItems()

> **extractItems**(`password`): `Promise`\<\{ `certificates`: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]; `privateKeys`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)[]; \}\>

#### Parameters

##### password

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<\{ `certificates`: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]; `privateKeys`: [`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)[]; \}\>

---

### getBags()

> **getBags**(`password`): `Promise`\<[`SafeBag`](../../SafeBag/classes/SafeBag.md)[]\>

#### Parameters

##### password

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`SafeBag`](../../SafeBag/classes/SafeBag.md)[]\>

---

### getBagsByName()

> **getBagsByName**(`bagName`, `password`): `Promise`\<[`SafeBag`](../../SafeBag/classes/SafeBag.md)[]\>

#### Parameters

##### bagName

`"KEY_BAG"` | `"PKCS8_SHROUDED_KEY_BAG"` | `"CERT_BAG"` | `"CRL_BAG"` | `"SECRET_BAG"` | `"SAFE_CONTENTS_BAG"`

##### password

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`SafeBag`](../../SafeBag/classes/SafeBag.md)[]\>

---

### getPrivateKeys()

> **getPrivateKeys**(`password`): `Promise`\<[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)[]\>

#### Parameters

##### password

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)[]\>

---

### getX509Certificates()

> **getX509Certificates**(`password`): `Promise`\<[`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]\>

#### Parameters

##### password

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]\>

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

Converts this PFX to its ASN.1 representation.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 SEQUENCE structure

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array`

Converts this PKI object to DER (Distinguished Encoding Rules) format.

#### Returns

`Uint8Array`

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

### create()

> `static` **create**(`options`): `Promise`\<`PFX`\>

Creates a new PFX instance containing the given certificates and private keys.

#### Parameters

##### options

Configuration object

###### certificates

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

Array of certificates to include

###### friendlyName?

`string`

Optional friendly name for the key/cert pairs

###### password

`string` \| `Uint8Array`\<`ArrayBufferLike`\>

Password to encrypt the private keys

###### privateKeys

[`PrivateKeyInfo`](../../../keys/PrivateKeyInfo/classes/PrivateKeyInfo.md)[]

Array of private keys to include

#### Returns

`Promise`\<`PFX`\>

A new PFX instance

---

### fromAsn1()

> `static` **fromAsn1**(`asn1`): `PFX`

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Returns

`PFX`

---

### fromDer()

> `static` **fromDer**(`der`): `PFX`

#### Parameters

##### der

`Uint8Array`

#### Returns

`PFX`

---

### fromPem()

> `static` **fromPem**(`pem`): `PFX`

#### Parameters

##### pem

`string`

#### Returns

`PFX`
