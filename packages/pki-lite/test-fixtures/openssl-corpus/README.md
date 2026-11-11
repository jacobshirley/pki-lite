# OpenSSL corpus

Valid DER structures produced by OpenSSL 3, used by `test/unit/openssl-corpus.test.ts` to
check that pki-lite can parse and faithfully re-encode what real tools emit.

Everything lives in `corpus.ts` (`family -> file name -> base64 DER`) so the test runs in
both the node and the browser vitest projects with no file access. To get a file back for
use with the OpenSSL CLI:

```sh
grep "'csr_plain_rsa.der'" corpus.ts | cut -d"'" -f4 | base64 -d | openssl req -inform DER -noout -subject
```

| Family | Contents                                                                                                                                                                                                                               |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cert` | X.509 certificates: every key/signature type OpenSSL offers, ~40 extension variants, name/string-type variety, validity (UTCTime/GeneralizedTime), serial-number edge cases, one cert per `GeneralName` type, v1 certificates (`v1_*`) |
| `csr`  | PKCS#10 requests (with/without attributes, extension requests)                                                                                                                                                                         |
| `crl`  | v1/v2 CRLs, empty CRLs, revocation reasons, IDP, GeneralizedTime dates                                                                                                                                                                 |
| `key`  | PKCS#8 (plain and PBES2/PBES1/scrypt encrypted), SPKI, PKCS#1, SEC1, ECDSA signatures                                                                                                                                                  |
| `cms`  | SignedData (attached/detached/multi-signer/BER-streamed), EnvelopedData (ktri/kari/kekri/pwri), EncryptedData, DigestedData                                                                                                            |
| `p12`  | PKCS#12 with default, legacy, AES, no-MAC, no-password and key-only/cert-only variants                                                                                                                                                 |
| `ocsp` | Requests and responses (good/revoked/unknown, nonce, error statuses)                                                                                                                                                                   |
| `ts`   | RFC 3161 time-stamping: queries (`q_*`), replies (`r_*`: granted with/without certs, nonce, policy, accuracy/ordering/TSA name, ESSCertIDv2, EC signer, rejected) and bare tokens (`tok_*`)                                            |

The CMS fixtures sign/encrypt the text `Hello, CMS world\n` (OpenSSL converts it to CRLF
unless `-binary` is used). PKCS#12 and encrypted PKCS#8 fixtures use the password `pw`
(`nopass.p12` uses the empty password). The time-stamp fixtures stamp `Hello, TSA world\n`.

OpenSSL 3 only writes v3 certificates, so `generate/05-*.sh` makes the `v1_*` ones by taking
the TBSCertificate of an extension-less certificate OpenSSL issued, removing its version
field, and signing the result with `openssl dgst` / `openssl pkeyutl`; `openssl x509` and
`openssl verify` check the outcome.

## Regenerating

```sh
./generate.sh            # needs an `openssl` 3.x and `xxd` on PATH
```

Keys are random, so regenerating replaces every entry. The test's `KNOWN_ISSUES` list
matches by file-name patterns rather than exact bytes, so it normally keeps working, but
re-run the test afterwards: a defect that was fixed shows up as a `test.fails` entry that
now fails ("expected to fail but passed"), which is the cue to delete that entry.
