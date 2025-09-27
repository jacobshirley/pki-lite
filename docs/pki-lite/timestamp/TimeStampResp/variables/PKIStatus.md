[**PKI-Lite v1.0.0**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [timestamp/TimeStampResp](../README.md) / PKIStatus

# Variable: PKIStatus

> `const` **PKIStatus**: `object`

PKI Status values as defined in RFC 3161.
These values indicate the result of a timestamp request.

## Type Declaration

### GRANTED

> `readonly` **GRANTED**: `0` = `0`

Request granted successfully

### GRANTED_WITH_MODS

> `readonly` **GRANTED_WITH_MODS**: `1` = `1`

Request granted with some modifications

### REJECTION

> `readonly` **REJECTION**: `2` = `2`

Request rejected

### REVOCATION_NOTIFICATION

> `readonly` **REVOCATION_NOTIFICATION**: `5` = `5`

Notification about certificate revocation

### REVOCATION_WARNING

> `readonly` **REVOCATION_WARNING**: `4` = `4`

Warning about certificate revocation

### WAITING

> `readonly` **WAITING**: `3` = `3`

Request is waiting for processing

## Example

```typescript
if (response.status.status === PKIStatus.GRANTED) {
    console.log('Timestamp successfully granted')
} else if (response.status.status === PKIStatus.REJECTION) {
    console.log('Timestamp request rejected')
}
```
