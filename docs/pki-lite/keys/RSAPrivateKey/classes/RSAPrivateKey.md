[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [keys/RSAPrivateKey](../README.md) / RSAPrivateKey

# Class: RSAPrivateKey

Represents an RSA private key as defined in RFC 8017 (PKCS #1 v2.2).

This class specifically implements the RSAPrivateKey ASN.1 structure from PKCS #1,
which differs from the generic PrivateKeyInfo structure defined in PKCS #8.

Use this class when:

- Working directly with RSA-specific parameters (modulus, exponents, etc.)
- Parsing or creating traditional RSA private key formats
- Need access to the Chinese Remainder Theorem (CRT) parameters

For general private key handling (including non-RSA keys), use PrivateKeyInfo instead.

## Asn

```asn
RSAPrivateKey ::= SEQUENCE {
    version           Version,  -- Integer, always 0 for two-prime, 1 for multi-prime
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

## Extends

- [`PkiBase`](../../../core/PkiBase/classes/PkiBase.md)\<`RSAPrivateKey`\>

## Constructors

### Constructor

> **new RSAPrivateKey**(`options`): `RSAPrivateKey`

Creates a new RSAPrivateKey instance.

#### Parameters

##### options

###### coefficient

`Uint8Array<ArrayBuffer>`

###### exponent1

`Uint8Array<ArrayBuffer>`

###### exponent2

`Uint8Array<ArrayBuffer>`

###### modulus

`Uint8Array<ArrayBuffer>`

###### prime1

`Uint8Array<ArrayBuffer>`

###### prime2

`Uint8Array<ArrayBuffer>`

###### privateExponent

`Uint8Array<ArrayBuffer>`

###### publicExponent

`Uint8Array<ArrayBuffer>`

###### version?

`number`

#### Returns

`RSAPrivateKey`

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`constructor`](../../../core/PkiBase/classes/PkiBase.md#constructor)

## Properties

### coefficient

> **coefficient**: `Uint8Array<ArrayBuffer>`

The CRT coefficient ((inverse of q) mod p)

---

### exponent1

> **exponent1**: `Uint8Array<ArrayBuffer>`

The first exponent (d mod (p-1))

---

### exponent2

> **exponent2**: `Uint8Array<ArrayBuffer>`

The second exponent (d mod (q-1))

---

### modulus

> **modulus**: `Uint8Array<ArrayBuffer>`

The modulus (n)

---

### prime1

> **prime1**: `Uint8Array<ArrayBuffer>`

The first prime factor (p)

---

### prime2

> **prime2**: `Uint8Array<ArrayBuffer>`

The second prime factor (q)

---

### privateExponent

> **privateExponent**: `Uint8Array<ArrayBuffer>`

The private exponent (d)

---

### publicExponent

> **publicExponent**: `Uint8Array<ArrayBuffer>`

The exponent (e)

---

### version

> **version**: `number`

The version (always 0 for two-prime RSA)

## Accessors

### pemHeader

#### Get Signature

> **get** **pemHeader**(): `string`

Gets the PEM header name for this object type.
Converts the class name to uppercase for use in PEM encoding.

##### Returns

`string`

#### Overrides

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

Converts the RSA private key to an ASN.1 structure.

#### Returns

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

#### Overrides

[`PkiBase`](../../../core/PkiBase/classes/PkiBase.md).[`toAsn1`](../../../core/PkiBase/classes/PkiBase.md#toasn1)

---

### toDer()

> **toDer**(): `Uint8Array<ArrayBuffer>`

Converts the RSA private key to DER format.

#### Returns

`Uint8Array<ArrayBuffer>`

#### Overrides

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

### toPublicKey()

> **toPublicKey**(): `any`

Extracts the RSA key component from this private key.

#### Returns

`any`

A new RSAPublicKey containing the parts of this key

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

> `static` **fromAsn1**(`asn1`): `RSAPrivateKey`

Parses an ASN.1 structure to create an RSAPrivateKey.

#### Parameters

##### asn1

[`Asn1BaseBlock`](../../../core/PkiBase/type-aliases/Asn1BaseBlock.md)

The ASN.1 structure

#### Returns

`RSAPrivateKey`

A new RSAPrivateKey instance

---

### fromDer()

> `static` **fromDer**(`der`): `RSAPrivateKey`

Parses DER encoded data to create an RSAPrivateKey.

#### Parameters

##### der

`Uint8Array<ArrayBuffer>`

The DER encoded data

#### Returns

`RSAPrivateKey`

A new RSAPrivateKey instance

---

### fromPem()

> `static` **fromPem**(`pem`): `RSAPrivateKey`

Parses PEM encoded data to create an RSAPrivateKey.

#### Parameters

##### pem

`string`

The PEM encoded data

#### Returns

`RSAPrivateKey`

A new RSAPrivateKey instance
