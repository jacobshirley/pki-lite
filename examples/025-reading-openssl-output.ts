// Reading certificates, requests, CRLs and OCSP responses created by OpenSSL

import { OIDs } from 'pki-lite/core/OIDs.js'
import { OCSPResponse } from 'pki-lite/ocsp/OCSPResponse.js'
import { CertificateList } from 'pki-lite/x509/CertificateList.js'
import { Certificate } from 'pki-lite/x509/Certificate.js'
import { CertificateRequest } from 'pki-lite/x509/CertificateRequest.js'

console.log('=== Reading OpenSSL output ===\n')

// These were made with, respectively:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...
//   openssl req -new -addext subjectAltName=DNS:a.example,IP:10.0.0.1 ...
//   openssl ca -gencrl ... (with revoked certificates)
//   openssl ocsp -index ... -respout ... (for a revoked certificate)
const certificatePem = `-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIUKBhZ2AVzxLzBZ5xE00YVIYFZDY4wCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEVGVzdDAeFw0yNjExMTExMjQ1NTZaFw0yNjEyMTExMjQ1NTZa
MA8xDTALBgNVBAMMBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT003m7
gsMFGNWU8O8fzRTWI6o44DX4nuAmfi0YWKA8rnnmxQPaTCcDk7bEHVQiylShCOgW
Pj42HyGICe7TwKOro1MwUTAdBgNVHQ4EFgQUyhtApj1b+4SbhqlJAIz9LlElD/sw
HwYDVR0jBBgwFoAUyhtApj1b+4SbhqlJAIz9LlElD/swDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNIADBFAiEAqeyvJDuaTtqMMICaAUg/3MLYP53DJWZ2hST+
jZ+/Mv0CIDds0y9CS2saR9taicfrW+4AAK5v4AK4gAMNLjB6PVa2
-----END CERTIFICATE-----`

const csrPem = `-----BEGIN CERTIFICATE REQUEST-----
MIICfjCCAWYCAQAwDDEKMAgGA1UEAwwBWDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAIlh38Wr3e7t7tZfLyJm9VU03i5VeFziZfgU87rlKEoncHDRdyJT
Czu9QPEtHHcYiFD52IKmASRRuvXx6cXueeA7/94lANz7m09EM5RHmzpQvsaP6F8C
WXFPff02gqgy5q4fPblxrQ9ZzTLLhdDHc92SKenRoaeKYZ5MqRo+5eJCvq1ONkIn
1LNZHugInBdIGInZz1+QGLyg2hT6SoeOB3RHl7HaA2Mo+NOl8/kV/w6raCDUqRJM
+ZKA+MQzD6w0s6HfJNml01p5WaxtpPnP3Z9phD4859xRr7FiQSC+9pACeAjxPmdC
JHtvjOCskS4SDDwb8YWrr2t6MGI1k69uMY8CAwEAAaAtMCsGCSqGSIb3DQEJDjEe
MBwwGgYDVR0RBBMwEYIJYS5leGFtcGxlhwQKAAABMA0GCSqGSIb3DQEBCwUAA4IB
AQBuaWHZXvm/gPcTDhJfomWHEtgNh2YOnoq4Giyq+g/IOCt2T4OLz+xlo+Jogmlq
bdsRWOnvocUkZyQlAYLWrJg23a1SDhAjzg+OQ4wnbzZaA7IBz+FO3vsQpI2qd26f
rNj65AKv6rGSa9a8exBXvQZsacXyrk2azfI/sEzbTFwxPO2M5+iuPJatWiLXniXR
Djirt4291X61APorU6s3FZd5qK0qa6+Z3qdNCdKXRTP30x3X3sRTjUdZ3LjN1oZG
zOLuOX5Srx/P8Aksf8xcCocNEAj1EjpAi1t1aSUz4gqT+WAf2pknpc9WF5EQYCZ2
9qOWfcqq4ANhe1244mZcpm77
-----END CERTIFICATE REQUEST-----`

const crlPem = `-----BEGIN X509 CRL-----
MIICuDCCAaACAQEwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHVGVzdCBDQRcN
MjYxMTExMTI0NTU4WhcNMjYxMTE4MTI0NTU4WjCCARwwEgIBARcNMjYxMTExMTI0
NTU4WjAgAgECFw0yNjExMTExMjQ1NThaMAwwCgYDVR0VBAMKAQEwIAIBAxcNMjYx
MTExMTI0NTU4WjAMMAoGA1UdFQQDCgECMCACAQQXDTI2MTExMTEyNDU1OFowDDAK
BgNVHRUEAwoBBjAgAgEFFw0yNjExMTExMjQ1NThaMAwwCgYDVR0VBAMKAQgwOgIB
BhcNMjYxMTExMTI0NTU4WjAmMAoGA1UdFQQDCgEBMBgGA1UdGAQRGA8yMDI0MDEw
MTAwMDAwMFowIAIBBxcNMjYxMTExMTI0NTU4WjAMMAoGA1UdFQQDCgEDMCACAQgX
DTI2MTExMTEyNDU1OFowDDAKBgNVHRUEAwoBAKA6MDgwHwYDVR0jBBgwFoAU3NAe
xUQTwAB+w3BNW3VMsMSvoP4wCQYDVR0SBAIwADAKBgNVHRQEAwIBAjANBgkqhkiG
9w0BAQsFAAOCAQEAiTvhbIOtZ8yRnwn3DGkc6FWN1SBJHTNzAET7lskaAGkScULp
MLzhUrZyq+YYo0OfBrh3WI2XeTUmQP8JtNOOFej2GhRzVMxWhevd5O2FyLJ2WFft
RkfvO1YdstatZZEmQkn6BlqumdbS4ngtBS6c18aEGMe9AneBGed7X0fmZmYenq1u
76OAVIeg9pLT7rarfn6auEhCTBMQ7RZtOQk4lABs1AV+dZn2A4UpfysIg5rTHaSP
+eJ0Oo3GpEUYRMJNUDpyFW/3tSqYPElMR6J5ywd9+e8V/G5nUS8sMMMXL142b/GX
uSVzWdoGbZmaguXYibZcWoMHS0sixYZhdPXFtw==
-----END X509 CRL-----`

const ocspBase64 = `MIIE4QoBAKCCBNowggTWBgkrBgEFBQcwAQEEggTHMIIEwzCBi6EUMBIxEDAOBgNV
BAMMB1Rlc3QgQ0EYDzIwMjYxMTExMTI0NTU4WjBiMGAwOjAJBgUrDgMCGgUABBS/
cFLIucD3YMiRI+CZgV6ywDlCJgQU3NAexUQTwAB+w3BNW3VMsMSvoP4CAQGhERgP
MjAyNjExMTExMjQ1NThaGA8yMDI2MTExMTEyNDU1OFowDQYJKoZIhvcNAQELBQAD
ggEBAAArbLxHIxpNFV210Be8CR1U03SxOmk/2gBqWrEv90+4KRc0rlAjxXjZMe+V
aNh+WNjk99uj7mC0l07Q+jD3LaMmD/+xjgpE6KTHqmeeVzQW6DPMQDbAKn+8yFfY
+jYHyO8clz0Y27j8qq8TnAPn6SWAluQnAy+zbRq7sWOqzkq4WE03j03vV9Q3wuIX
24qv3waPP0mwaufCn7NBkGcA2MIw5AHb5T4TuIBulkWZ1EIDRCRPfcHXPSbZhXKg
4bXn2yOIQJCqd0LoAl+38lNGj5bfgav4elOmpJa17E6ozssJFsqa6m1ND9l2C0Xo
fQnuk23kYcyDTcvS9lKKtQJzCmSgggMdMIIDGTCCAxUwggH9oAMCAQICFClgLppy
ennxRqJk/06fVW8A2zxnMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMMB1Rlc3Qg
Q0EwHhcNMjYxMTExMTI0NTU4WhcNMjcxMTExMTI0NTU4WjASMRAwDgYDVQQDDAdU
ZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiWHfxavd7u3u
1l8vImb1VTTeLlV4XOJl+BTzuuUoSidwcNF3IlMLO71A8S0cdxiIUPnYgqYBJFG6
9fHpxe554Dv/3iUA3PubT0QzlEebOlC+xo/oXwJZcU99/TaCqDLmrh89uXGtD1nN
MsuF0Mdz3ZIp6dGhp4phnkypGj7l4kK+rU42QifUs1ke6AicF0gYidnPX5AYvKDa
FPpKh44HdEeXsdoDYyj406Xz+RX/DqtoINSpEkz5koD4xDMPrDSzod8k2aXTWnlZ
rG2k+c/dn2mEPjzn3FGvsWJBIL72kAJ4CPE+Z0Ike2+M4KyRLhIMPBvxhauva3ow
YjWTr24xjwIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjAdBgNVHQ4EFgQU3NAexUQTwAB+w3BNW3VMsMSvoP4wHwYDVR0jBBgwFoAU3NAe
xUQTwAB+w3BNW3VMsMSvoP4wDQYJKoZIhvcNAQELBQADggEBAID7T9q5JYLRMS1W
l51WYvpRd0Pjn4L9j+WWwRfW8Nfiw7nys+hrFlqf9acw3wbTfztQXw9z0tve79Du
QKSAOeWHogZqe791zDYHKKv8vhdUgDK8m2/RkIXUtz+zoiGkbj8R+nRj4t2RI+cw
ltHq53eY5FLHPvTFBGtLCzhW18btQulUoI8rHh68RJ9n1eXnT1tQz4TqINBCb7YB
hq5kBY3inLkVNF5OOdxWp58q9wAtGmx4gHO8xLLcJfoLp1MqyYxDwSbTVzXtTAkv
07wQFwChFMGNAF+LRqSYSq99STgm3CmEljRerUQP7O2dB8AVIJRuCLvaY+raY/QR
JrJhLMw=`

// --- A certificate ---
const certificate = Certificate.fromPem(certificatePem)
console.log('Certificate')
console.log('  Subject:', certificate.tbsCertificate.subject.toHumanString())
console.log(
    '  Signature:',
    certificate.signatureAlgorithm.algorithm.friendlyName,
)
console.log(
    '  Valid:',
    certificate.tbsCertificate.validity.notBefore.toISOString(),
    'to',
    certificate.tbsCertificate.validity.notAfter.toISOString(),
)
console.log(
    '  Self-signed and signature valid:',
    await certificate.isSelfSigned(),
)

// --- A certificate signing request ---
const csr = CertificateRequest.fromPem(csrPem)
console.log('\nCertificate request')
console.log('  Subject:', csr.requestInfo.subject.toHumanString())
console.log(
    '  Public key:',
    csr.requestInfo.publicKey.algorithm.algorithm.friendlyName,
)
for (const attribute of csr.requestInfo.attributes ?? []) {
    console.log('  Attribute:', attribute.type.friendlyName)
}

// --- A CRL ---
const crl = CertificateList.fromPem(crlPem)
const revoked = crl.tbsCertList.revokedCertificates ?? []
console.log('\nCRL from', crl.tbsCertList.issuer.toHumanString())
console.log('  This update:', crl.tbsCertList.thisUpdate.toISOString())
console.log('  Next update:', crl.tbsCertList.nextUpdate?.toISOString())
console.log('  Revoked certificates:', revoked.length)
for (const entry of revoked.slice(0, 3)) {
    const hasReason = entry.crlEntryExtensions?.some(
        (extension) =>
            extension.extnID.value === OIDs.EXTENSION.CRL_REASON_CODE,
    )
    console.log(
        '   ',
        entry.userCertificate,
        'revoked',
        entry.revocationDate.toISOString(),
        hasReason ? '(with a reason code)' : '',
    )
}

// --- An OCSP response ---
const ocsp = OCSPResponse.fromDer(
    Uint8Array.from(atob(ocspBase64.replace(/\s/g, '')), (c) =>
        c.charCodeAt(0),
    ),
)
console.log(
    '\nOCSP response status code:',
    ocsp.responseStatus.value,
    '(0 = successful)',
)
const single = ocsp.getBasicOCSPResponse().tbsResponseData.responses[0]
console.log('  Certificate status:', single.certStatus.status)
console.log('  Revoked at:', single.certStatus.revocationTime?.toISOString())
console.log('  This update:', single.thisUpdate.time.toISOString())
