[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / emailWithin

# Function: emailWithin()

> **emailWithin**(`mailbox`, `constraint`): `boolean`

rfc822Name constraint (RFC 5280 4.2.1.10): a full mailbox matches that mailbox only; a
host ("example.com") matches mailboxes on exactly that host; a leading dot
(".example.com") matches mailboxes on any subdomain host.

## Parameters

### mailbox

`string`

### constraint

`string`

## Returns

`boolean`
