# Security Policy

## Overview

PKI-Lite is a cryptographic library that provides Public Key Infrastructure (PKI) operations. Security is of paramount importance for this project, as it handles sensitive cryptographic operations including certificate management, digital signatures, and key operations.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PKI-Lite, please report it privately using one of the following methods:

### Preferred Method: Security Advisory

1. Go to the [Security tab](https://github.com/jacobshirley/pki-lite/security) of this repository
2. Click "Report a vulnerability"
3. Fill out the security advisory form with details about the vulnerability

### Alternative Method: Email

Send details to: [jakeshirley2@gmail.com](mailto:jakeshirley2@gmail.com)

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact and severity
- Any suggested fixes or mitigations
- Your contact information for follow-up

## Security Response Process

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
2. **Investigation**: We will investigate the issue and determine its severity and impact
3. **Fix Development**: We will develop and test a fix for the vulnerability
4. **Disclosure**: We will coordinate with you on the disclosure timeline
5. **Release**: We will release a patched version and publish a security advisory

## Security Best Practices

When using PKI-Lite in your applications, please follow these security best practices:

### Key Management

- **Generate strong keys**: Use appropriate key sizes (RSA ≥ 2048 bits, ECDSA ≥ 256 bits)
- **Secure key storage**: Store private keys securely and never expose them in logs or error messages
- **Key rotation**: Implement regular key rotation policies
- **Hardware Security Modules (HSMs)**: Consider using HSMs for high-security environments

### Certificate Validation

- **Full chain validation**: Always validate the complete certificate chain
- **Revocation checking**: Implement proper CRL and OCSP checking
- **Certificate expiration**: Regularly monitor and renew certificates before expiration
- **Trusted root stores**: Maintain and update trusted root certificate stores

### Cryptographic Operations

- **Use recommended algorithms**: Prefer modern, secure algorithms over legacy ones
- **Secure random number generation**: Ensure proper entropy for cryptographic operations
- **Timing attack prevention**: Be aware of potential timing attacks in cryptographic operations
- **Memory management**: Clear sensitive data from memory when no longer needed

### Implementation Guidelines

- **Input validation**: Validate all inputs, especially when parsing certificates or keys
- **Error handling**: Implement secure error handling that doesn't leak sensitive information
- **Logging**: Avoid logging sensitive cryptographic material
- **Dependencies**: Keep dependencies updated and monitor for security vulnerabilities

## Known Security Considerations

## Cryptographic Limitations

- This library relies on the underlying JavaScript runtime's cryptographic capabilities
- Web browsers may have limitations on cryptographic operations
- Node.js environments provide more complete cryptographic support

### ASN.1 Parsing

- ASN.1 parsing can be complex and error-prone
- Malformed ASN.1 data could potentially cause issues
- We recommend validating ASN.1 structures from untrusted sources

## Security Testing

We encourage security testing and welcome reports of security issues. When conducting security testing:

1. **Responsible disclosure**: Follow responsible disclosure practices
2. **No disruption**: Do not disrupt services or access unauthorized data
3. **Documentation**: Document your findings clearly
4. **Coordination**: Coordinate with us before public disclosure

## License and Disclaimer

This software is provided under the MIT License. While we make every effort to ensure security, users are responsible for:

- Conducting their own security assessments
- Implementing appropriate security controls for their use case
- Staying informed about security updates and best practices

---

_Last updated: October 2025_
