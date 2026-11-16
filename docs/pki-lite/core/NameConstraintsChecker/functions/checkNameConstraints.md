[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/NameConstraintsChecker](../README.md) / checkNameConstraints

# Function: checkNameConstraints()

> **checkNameConstraints**(`certificate`, `constraints`): `undefined` \| [`NameConstraintViolation`](../type-aliases/NameConstraintViolation.md)

Checks a certificate against the name constraints of a CA (RFC 5280 4.2.1.10, 6.1.3(b)
and (c)).

- For each kind of name, a name is acceptable only if it is inside at least one
  _permitted_ subtree of that kind (when the CA permits any of that kind), and inside no
  _excluded_ subtree.
- Kinds the constraints say nothing about are unrestricted.
- Anything that cannot be evaluated fails closed: constraints on name types this
  checker has no matching rules for (otherName, ...) when the certificate has such a
  name, and subtrees that use `minimum`/`maximum` (RFC 5280 forbids them).
- A subject common name that looks like a host name is checked as a dNSName when the
  certificate has no dNSName in its subjectAltName. RFC 5280 does not do this, but TLS
  clients have long fallen back to the CN; it can only make the check stricter.

## Parameters

### certificate

[`Certificate`](../../../x509/Certificate/classes/Certificate.md)

### constraints

[`NameConstraints`](../../../x509/extensions/NameConstraints/classes/NameConstraints.md)

## Returns

`undefined` \| [`NameConstraintViolation`](../type-aliases/NameConstraintViolation.md)

the first violation, or `undefined` if the certificate satisfies the constraints
