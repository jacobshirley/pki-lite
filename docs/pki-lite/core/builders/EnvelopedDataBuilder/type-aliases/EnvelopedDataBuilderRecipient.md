[**PKI-Lite v1.0.0**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/builders/EnvelopedDataBuilder](../README.md) / EnvelopedDataBuilderRecipient

# Type Alias: EnvelopedDataBuilderRecipient

> **EnvelopedDataBuilderRecipient** = `object`

Configuration for a recipient of enveloped data.

## Example

```typescript
const recipient: EnvelopedDataBuilderRecipient = {
    certificate: recipientCert,
    keyEncryptionAlgorithm: {
        type: 'RSA_OAEP',
        params: { hash: 'SHA-384' },
    },
}
```

## Properties

### certificate

> **certificate**: [`Certificate`](../../../../x509/Certificate/classes/Certificate.md)

The recipient's certificate containing their public key

---

### keyEncryptionAlgorithm?

> `optional` **keyEncryptionAlgorithm**: [`AsymmetricEncryptionAlgorithmParams`](../../../crypto/types/type-aliases/AsymmetricEncryptionAlgorithmParams.md)

Optional key encryption algorithm, defaults to RSA-OAEP with SHA-1
