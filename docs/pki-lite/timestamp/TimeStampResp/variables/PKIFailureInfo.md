[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [timestamp/TimeStampResp](../README.md) / PKIFailureInfo

# Variable: PKIFailureInfo

> `const` **PKIFailureInfo**: `object`

PKI Failure Info bit flags as defined in RFC 3161.
These provide specific information about why a request failed.

## Type Declaration

### ADD_INFO_NOT_AVAILABLE

> `readonly` **ADD_INFO_NOT_AVAILABLE**: `17` = `17`

The additional information requested could not be understood or is not available

### BAD_ALG

> `readonly` **BAD_ALG**: `0` = `0`

Unrecognized or unsupported algorithm identifier

### BAD_DATA_FORMAT

> `readonly` **BAD_DATA_FORMAT**: `5` = `5`

The data submitted has the wrong format

### BAD_REQUEST

> `readonly` **BAD_REQUEST**: `2` = `2`

Transaction not permitted or supported

### SYSTEM_FAILURE

> `readonly` **SYSTEM_FAILURE**: `25` = `25`

The request cannot be handled due to system failure

### TIME_NOT_AVAILABLE

> `readonly` **TIME_NOT_AVAILABLE**: `14` = `14`

The TSA's time source is not available

### UNACCEPTED_EXTENSION

> `readonly` **UNACCEPTED_EXTENSION**: `16` = `16`

The requested extension is not supported

### UNACCEPTED_POLICY

> `readonly` **UNACCEPTED_POLICY**: `15` = `15`

The requested TSA policy is not supported

## Example

```typescript
if (response.status.failInfo === PKIFailureInfo.BAD_ALG) {
    console.log('Unrecognized or unsupported algorithm')
}
```
