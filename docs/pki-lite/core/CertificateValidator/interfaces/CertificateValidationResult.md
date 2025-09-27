[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / CertificateValidationResult

# Interface: CertificateValidationResult

Result of certificate validation.

## Properties

### certificate

> **certificate**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)

The certificate that was validated

---

### chain?

> `optional` **chain**: [`CertificateChain`](CertificateChain.md)

Certificate chain information (if chain validation was performed)

---

### diagnostics

> **diagnostics**: `object`

Diagnostic information for troubleshooting

#### context

> **context**: `Record`\<`string`, `any`\>

Additional context information

#### stepsPerformed

> **stepsPerformed**: `string`[]

Validation steps performed

#### warnings

> **warnings**: `string`[]

Warnings encountered during validation

---

### isValid

> **isValid**: `boolean`

Whether the certificate is valid

---

### messages

> **messages**: `string`[]

Detailed validation messages

---

### policyResult?

> `optional` **policyResult**: [`PolicyValidationResult`](PolicyValidationResult.md)

Policy validation result (if policy validation was performed)

---

### revocationStatus

> **revocationStatus**: [`RevocationStatus`](RevocationStatus.md)

Revocation status information

---

### status

> **status**: [`CertificateValidationStatus`](../type-aliases/CertificateValidationStatus.md)

Overall validation status

---

### validatedAt

> **validatedAt**: `Date`

Validation timestamp
