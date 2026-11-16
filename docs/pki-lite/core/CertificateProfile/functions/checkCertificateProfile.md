[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/CertificateProfile](../README.md) / checkCertificateProfile

# Function: checkCertificateProfile()

> **checkCertificateProfile**(`certificate`, `options`): `string`[]

Where a certificate breaks the RFC 5280 certificate profile: the rules for what
conforming CAs issue (section 4), as opposed to the path validation algorithm
(section 6). Many real PKIs break some of them, so CertificateValidator checks them only
with `strictProfile`, as OpenSSL does only with its X509_STRICT flag.

A trust anchor is checked as a CA, but not for the rules about how it was issued (its
serial number, and an authorityKeyIdentifier when it is not self-signed): RFC 5280 does
not validate trust anchor information, and real roots break them (fastly.com's chain
ends at a Starfield root with serial number 0).

## Parameters

### certificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

The certificate to check

### options

#### trustAnchor?

`boolean`

Whether it is the trust anchor of the path

## Returns

`string`[]

A description of each problem found (none if it conforms)
