[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/utils](../README.md) / pkcs12Derive

# Function: pkcs12Derive()

> **pkcs12Derive**(`password`, `salt`, `id`, `iterations`, `n`, `hash`): `Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>

PKCS#12 password-based key derivation (RFC 7292 Appendix B.2).

## Parameters

### password

`Uint8Array`\<`ArrayBuffer`\>

Password as BMPString (UTF-16BE) with NUL terminator

### salt

`Uint8Array`\<`ArrayBuffer`\>

Salt bytes

### id

1 = encryption key, 2 = IV, 3 = MAC key

`1` | `2` | `3`

### iterations

`number`

Iteration count

### n

`number`

Number of bytes to produce

### hash

[`HashAlgorithm`](../../types/type-aliases/HashAlgorithm.md)

Hash algorithm

## Returns

`Promise`\<`Uint8Array`\<`ArrayBuffer`\>\>
