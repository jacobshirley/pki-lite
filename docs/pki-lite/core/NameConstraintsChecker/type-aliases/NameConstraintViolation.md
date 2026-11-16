[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / NameConstraintViolation

# Type Alias: NameConstraintViolation

> **NameConstraintViolation** = `object`

Why a certificate was rejected by a name constraint.

## Properties

### message

> **message**: `string`

A readable explanation

---

### name

> **name**: `string`

The offending name, e.g. `www.example.com`

---

### type

> **type**: `string`

What kind of name it is, e.g. `dNSName`
