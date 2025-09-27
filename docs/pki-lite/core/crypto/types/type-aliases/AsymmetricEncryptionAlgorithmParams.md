[**PKI-Lite**](../../../../../README.md)

---

[PKI-Lite](../../../../../README.md) / [pki-lite](../../../../README.md) / [core/crypto/types](../README.md) / AsymmetricEncryptionAlgorithmParams

# Type Alias: AsymmetricEncryptionAlgorithmParams

> **AsymmetricEncryptionAlgorithmParams** = `{ [K in keyof AsymmetricEncryptionAlgorithmParamsMap]: { params: AsymmetricEncryptionAlgorithmParamsMap[K]; type: K } }`\[keyof [`AsymmetricEncryptionAlgorithmParamsMap`](../interfaces/AsymmetricEncryptionAlgorithmParamsMap.md)\]

Discriminated union type for asymmetric algorithm parameters.
Each algorithm type includes its specific parameter set.
