[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [ocsp/OCSPRequest](../README.md) / nonceOf

# Function: nonceOf()

> **nonceOf**(`extensions`): `undefined` \| `Uint8Array`\<`ArrayBuffer`\>

**`Internal`**

The nonce (RFC 8954) in a list of extensions: an OCTET STRING, or (from some older
responders) the raw bytes.

## Parameters

### extensions

`undefined` | [`Extension`](../../../x509/Extension/classes/Extension.md)[]

## Returns

`undefined` \| `Uint8Array`\<`ArrayBuffer`\>
