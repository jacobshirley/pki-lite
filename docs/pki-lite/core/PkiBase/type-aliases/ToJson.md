[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PkiBase](../README.md) / ToJson

# Type Alias: ToJson\<T\>

> **ToJson**\<`T`\> = `{ [K in keyof T]: T[K] extends object ? ToJson<T[K]> : T[K] }`

## Type Parameters

### T

`T`
