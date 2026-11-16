[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CrlChecker](../README.md) / CrlChecker

# Class: CrlChecker

Determines a certificate's revocation status from CRLs as RFC 5280 6.3 describes:
complete CRLs (and delta CRLs on top of them) are used only if they are issued for the
certificate (directly or, for an indirect CRL, by a cRLIssuer the certificate names),
apply to it (issuingDistributionPoint scope), are current, have no critical extension
this checker cannot process, and are signed by a key whose certificate allows CRL
signing and validates. A certificate is "good" only if such CRLs cover every
revocation reason; otherwise its status is undetermined.

For a single CRL, `crl.verify(issuer)`, `crl.isCurrent()` and `crl.isRevoked(cert)` do
the individual checks; CertificateValidator uses this class with `checkCRL`.

## Constructors

### Constructor

> **new CrlChecker**(`options`): `CrlChecker`

#### Parameters

##### options

[`CrlCheckerOptions`](../type-aliases/CrlCheckerOptions.md)

#### Returns

`CrlChecker`

## Methods

### check()

> **check**(`certificate`): `Promise`\<[`CrlStatus`](../type-aliases/CrlStatus.md)\>

#### Parameters

##### certificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

#### Returns

`Promise`\<[`CrlStatus`](../type-aliases/CrlStatus.md)\>
