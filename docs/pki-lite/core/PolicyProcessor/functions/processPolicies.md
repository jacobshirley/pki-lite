[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/PolicyProcessor](../README.md) / processPolicies

# Function: processPolicies()

> **processPolicies**(`path`, `isSelfIssued`, `options`): [`PolicyProcessingResult`](../interfaces/PolicyProcessingResult.md)

Certificate policy processing of RFC 5280 6.1 (the valid_policy_tree, the explicit_policy,
policy_mapping and inhibit_anyPolicy counters).

## Parameters

### path

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

the certification path from the leaf to the CA below the trust anchor (the
trust anchor itself is not part of it)

### isSelfIssued

(`certificate`) => `boolean`

whether a certificate's issuer and subject are the same

### options

[`PolicyProcessingOptions`](../interfaces/PolicyProcessingOptions.md) = `{}`

## Returns

[`PolicyProcessingResult`](../interfaces/PolicyProcessingResult.md)
