# OpenSSL corpus

Valid DER structures produced by OpenSSL 3, used by `test/node/openssl-corpus.test.ts` to
check that pki-lite can parse and faithfully re-encode what real tools emit.

| Directory | Contents |
|-----------|----------|
| `cert/`   | X.509 certificates: every key/signature type OpenSSL offers, ~40 extension variants, name/string-type variety, validity (UTCTime/GeneralizedTime), serial-number edge cases, one cert per `GeneralName` type |
| `csr/`    | PKCS#10 requests (with/without attributes, extension requests) |
| `crl/`    | v1/v2 CRLs, empty CRLs, revocation reasons, IDP, GeneralizedTime dates |
| `key/`    | PKCS#8 (plain and PBES2/PBES1/scrypt encrypted), SPKI, PKCS#1, SEC1, ECDSA signatures |
| `cms/`    | SignedData (attached/detached/multi-signer/BER-streamed), EnvelopedData (ktri/kari/kekri/pwri), EncryptedData, DigestedData |
| `p12/`    | PKCS#12 with default, legacy, AES, no-MAC, no-password and key-only/cert-only variants |
| `ocsp/`   | Requests and responses (good/revoked/unknown, nonce, error statuses) |

The CMS fixtures sign/encrypt the text `Hello, CMS world\n` (OpenSSL converts it to CRLF
unless `-binary` is used). PKCS#12 and encrypted PKCS#8 fixtures use the password `pw`
(`nopass.p12` uses the empty password).

## Regenerating

```sh
./generate.sh            # needs an `openssl` 3.x on PATH
```

Keys are random, so regenerating replaces every file. The test's `KNOWN_ISSUES` list
matches by file-name patterns rather than exact bytes, so it normally keeps working, but
re-run the test afterwards: a defect that was fixed shows up as a `test.fails` entry that
now fails ("expected to fail but passed"), which is the cue to delete that entry.
