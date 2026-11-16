[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateValidator](../README.md) / CertificateValidationOptions

# Interface: CertificateValidationOptions

Options for certificate validation.

## Properties

### checkCRL?

> `optional` **checkCRL**: `boolean`

Check certificate revocation using CRLs, as RFC 5280 6.3 describes: a CRL counts only
if it is issued for the certificate (directly, or as an indirect CRL by a cRLIssuer
the certificate names), its issuingDistributionPoint scope covers the certificate, it
is current (thisUpdate <= time <= nextUpdate), it has no critical extension that is
not understood, and it is signed by a certificate with cRLSign whose path validates
(delta CRLs are applied on top). Every certificate below the trust anchor needs CRLs
covering all revocation reasons (or an OCSP answer, with `checkOCSP`); otherwise the
result is `CRL_UNAVAILABLE`, including when no revocation data is passed to
`validate`.

---

### checkOCSP?

> `optional` **checkOCSP**: `boolean`

Check certificate revocation using OCSP (RFC 6960): a response counts only if it is
successful, gives a current status for this certificate from its issuer, and is
signed by the issuer or a responder it authorised. With `checkCRL` too, CRLs decide
when no response does. Otherwise every certificate below the trust anchor needs such
a response, or the result is `OCSP_UNAVAILABLE`, including when no revocation data
is passed to `validate`.

---

### checkSignature?

> `optional` **checkSignature**: `boolean`

Whether to verify each certificate's signature with its issuer's public key
(RFC 5280 6.1.3 (a)(1)). On by default; set to `false` only for certificates
whose signatures were checked some other way.

---

### enforceCAConstraints?

> `optional` **enforceCAConstraints**: `boolean`

Whether to enforce CA constraints on the issuing certificates (RFC 5280 6.1.4):
basicConstraints cA, keyUsage keyCertSign and pathLenConstraint. On by default.

---

### fetchIssuerCertificates?

> `optional` **fetchIssuerCertificates**: `boolean` \| \{ `timeout?`: `number`; \}

Whether path building may download a missing issuer from the caIssuers URL of a
certificate's authorityInfoAccess extension (http and https only; optionally with a
per-request `timeout` in milliseconds, 10,000 by default). Off by default: the URLs
come from the certificates being validated, so following them makes requests
wherever those certificates point, and validation then depends on the network.
Pass the intermediates in `otherCertificates` instead where you can.

---

### hostname?

> `optional` **hostname**: `string`

The DNS name or IP address the certificate must be valid for, as a TLS client
checks a server (RFC 9525; see [Certificate.matchesHostname](../../../x509/Certificate/classes/Certificate.md#matcheshostname)). If the
certificate does not match, the result is `HOSTNAME_MISMATCH`.

---

### initialAnyPolicyInhibit?

> `optional` **initialAnyPolicyInhibit**: `boolean`

initial-any-policy-inhibit: anyPolicy is not treated as a match

---

### initialExplicitPolicy?

> `optional` **initialExplicitPolicy**: `boolean`

initial-explicit-policy: an acceptable policy is required even if no certificate asks for it

---

### initialPolicyMappingInhibit?

> `optional` **initialPolicyMappingInhibit**: `boolean`

initial-policy-mapping-inhibit: policy mappings are not allowed

---

### initialPolicySet?

> `optional` **initialPolicySet**: `string`[]

user-initial-policy-set: the path must be valid for at least one of these (default: any)

---

### maxPathLength?

> `optional` **maxPathLength**: `number`

The most intermediate CA certificates a path may have, not counting self-issued
ones: a pathLenConstraint the relying party sets on the trust anchor (RFC 5280
6.1.1 (k)). Part of chain validation.

---

### otherCertificates?

> `optional` **otherCertificates**: [`Certificate`](../../../x509/Certificate/classes/Certificate.md)[]

Other certificates available for chain building

---

### requiredExtendedKeyUsages?

> `optional` **requiredExtendedKeyUsages**: `string`[]

Extended key usages the certificate must allow (by common name, e.g. `serverAuth`,
or OID; see [Certificate.allowsExtendedKeyUsage](../../../x509/Certificate/classes/Certificate.md#allowsextendedkeyusage)). If it does not, the result
is `EXTENDED_KEY_USAGE_NOT_ALLOWED`.

---

### requiredPolicies?

> `optional` **requiredPolicies**: `string`[]

Policy OIDs that must all be valid for the path (implies an explicit policy), in the
trust anchor's policy domain like `initialPolicySet`: with policy mappings, a policy
as the first CA asserts it, not as the leaf does

---

### strictProfile?

> `optional` **strictProfile**: `boolean`

Whether to enforce the RFC 5280 certificate and CRL profiles: the rules for what
conforming CAs issue (sections 4 and 5), beyond the path validation algorithm. For
every certificate in the path, the trust anchor included: extension criticality
(AKI, SKI, AIA non-critical; basicConstraints in a CA, nameConstraints,
policyConstraints critical), required extensions (authorityKeyIdentifier,
subjectKeyIdentifier in CAs), no duplicate extensions, positive serial numbers of at
most 20 octets, well-formed subjectAltName names and name constraints, and no
unrecognised critical extension in the trust anchor. For CRLs: cRLNumber present
and non-critical, and no serial number listed twice. Off by default (many real PKIs
break some of these rules), as OpenSSL checks them only with X509_STRICT.
Part of chain validation.

---

### timeTolerance?

> `optional` **timeTolerance**: `number`

Tolerance for time-based validations (in milliseconds)

---

### trustAnchors?

> `optional` **trustAnchors**: [`TrustAnchor`](TrustAnchor.md)[]

Trust anchors to use for chain validation

---

### validateChain?

> `optional` **validateChain**: `boolean`

Whether to build and validate the full certificate chain

---

### validateNameConstraints?

> `optional` **validateNameConstraints**: `boolean`

Whether to enforce name constraints (RFC 5280 4.2.1.10): the `NameConstraints`
extension of every CA in the chain, and any given with the trust anchor, apply to the
certificates below them. On by default, as RFC 5280 requires of path validation; set
to `false` to skip the check. Part of chain validation (`validateChain`).

---

### validatePolicies?

> `optional` **validatePolicies**: `boolean`

Whether to process certificate policies (RFC 5280 6.1). On by default.

---

### validationTime?

> `optional` **validationTime**: `Date`

Custom validation date (defaults to current time)
