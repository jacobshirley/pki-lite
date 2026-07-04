[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/OIDs](../README.md) / OIDs

# Variable: OIDs

> `const` **OIDs**: `object`

Object Identifiers (OIDs) for cryptographic algorithms, data formats, and PKI standards.

## Type Declaration

### ADOBE

> `readonly` **ADOBE**: `object`

Adobe OIDs

#### ADOBE.REVOCATION_INFO_ARCHIVAL

> `readonly` **REVOCATION_INFO_ARCHIVAL**: `"1.2.840.113583.1.1.8"` = `'1.2.840.113583.1.1.8'`

Revocation Info Archival

### AUTHORITY_INFO_ACCESS

> `readonly` **AUTHORITY_INFO_ACCESS**: `object`

AUTHORITY_INFO_ACCESS extension access methods

#### AUTHORITY_INFO_ACCESS.CA_ISSUERS

> `readonly` **CA_ISSUERS**: `"1.3.6.1.5.5.7.48.2"` = `'1.3.6.1.5.5.7.48.2'`

CA Issuers

#### AUTHORITY_INFO_ACCESS.OCSP

> `readonly` **OCSP**: `"1.3.6.1.5.5.7.48.1"` = `'1.3.6.1.5.5.7.48.1'`

OCSP

### CURVES

> `readonly` **CURVES**: `object`

Named Elliptic Curves

#### CURVES.ED25519

> `readonly` **ED25519**: `"1.3.101.112"` = `'1.3.101.112'`

Ed25519 curve for EdDSA

#### CURVES.ED448

> `readonly` **ED448**: `"1.3.101.113"` = `'1.3.101.113'`

Ed448 curve for EdDSA

#### CURVES.SECP256K1

> `readonly` **SECP256K1**: `"1.3.132.0.10"` = `'1.3.132.0.10'`

secp256k1 (used in Bitcoin and other cryptocurrencies)

#### CURVES.SECP256R1

> `readonly` **SECP256R1**: `"1.2.840.10045.3.1.7"` = `'1.2.840.10045.3.1.7'`

NIST P-256 / secp256r1

#### CURVES.SECP384R1

> `readonly` **SECP384R1**: `"1.3.132.0.34"` = `'1.3.132.0.34'`

NIST P-384 / secp384r1

#### CURVES.SECP521R1

> `readonly` **SECP521R1**: `"1.3.132.0.35"` = `'1.3.132.0.35'`

NIST P-521 / secp521r1

#### CURVES.X25519

> `readonly` **X25519**: `"1.3.101.110"` = `'1.3.101.110'`

X25519 curve for ECDH

#### CURVES.X448

> `readonly` **X448**: `"1.3.101.111"` = `'1.3.101.111'`

X448 curve for ECDH

### DN

> `readonly` **DN**: `object`

Distinguished Name (DN) components

#### DN.C

> `readonly` **C**: `"2.5.4.6"` = `'2.5.4.6'`

Country

#### DN.CN

> `readonly` **CN**: `"2.5.4.3"` = `'2.5.4.3'`

Common Name

#### DN.EMAIL

> `readonly` **EMAIL**: `"1.2.840.113549.1.9.1"` = `'1.2.840.113549.1.9.1'`

Email Address (PKCS#9)

#### DN.L

> `readonly` **L**: `"2.5.4.7"` = `'2.5.4.7'`

Locality

#### DN.O

> `readonly` **O**: `"2.5.4.10"` = `'2.5.4.10'`

Organization

#### DN.OU

> `readonly` **OU**: `"2.5.4.11"` = `'2.5.4.11'`

Organizational Unit

#### DN.ST

> `readonly` **ST**: `"2.5.4.8"` = `'2.5.4.8'`

State or Province

### DSA

> `readonly` **DSA**: `object`

DSA Algorithms

#### DSA.ALGORITHM

> `readonly` **ALGORITHM**: `"1.2.840.10040.4.1"` = `'1.2.840.10040.4.1'`

Digital Signature Algorithm

#### DSA.SHA1_WITH_DSA

> `readonly` **SHA1_WITH_DSA**: `"1.2.840.10040.4.3"` = `'1.2.840.10040.4.3'`

SHA-1 with DSA Signature

#### DSA.SHA256_WITH_DSA

> `readonly` **SHA256_WITH_DSA**: `"2.16.840.1.101.3.4.3.2"` = `'2.16.840.1.101.3.4.3.2'`

SHA-256 with DSA Signature

### EC

> `readonly` **EC**: `object`

Elliptic Curve Cryptography

#### EC.ECDH

> `readonly` **ECDH**: `"1.2.840.10045.3.1.1"` = `'1.2.840.10045.3.1.1'`

Elliptic Curve Diffie-Hellman (ECDH)

#### EC.PUBLIC_KEY

> `readonly` **PUBLIC_KEY**: `"1.2.840.10045.2.1"` = `'1.2.840.10045.2.1'`

Elliptic Curve Public Key

#### EC.SHA1_WITH_ECDSA

> `readonly` **SHA1_WITH_ECDSA**: `"1.2.840.10045.4.1"` = `'1.2.840.10045.4.1'`

SHA-1 with ECDSA Signature

#### EC.SHA256_WITH_ECDSA

> `readonly` **SHA256_WITH_ECDSA**: `"1.2.840.10045.4.3.2"` = `'1.2.840.10045.4.3.2'`

SHA-256 with ECDSA Signature

#### EC.SHA384_WITH_ECDSA

> `readonly` **SHA384_WITH_ECDSA**: `"1.2.840.10045.4.3.3"` = `'1.2.840.10045.4.3.3'`

SHA-384 with ECDSA Signature

#### EC.SHA512_WITH_ECDSA

> `readonly` **SHA512_WITH_ECDSA**: `"1.2.840.10045.4.3.4"` = `'1.2.840.10045.4.3.4'`

SHA-512 with ECDSA Signature

### EKU

> `readonly` **EKU**: `object`

Extended Key Usage Purpose OIDs

#### EKU.CLIENT_AUTH

> `readonly` **CLIENT_AUTH**: `"1.3.6.1.5.5.7.3.2"` = `'1.3.6.1.5.5.7.3.2'`

TLS Web Client Authentication

#### EKU.CODE_SIGNING

> `readonly` **CODE_SIGNING**: `"1.3.6.1.5.5.7.3.3"` = `'1.3.6.1.5.5.7.3.3'`

Code Signing

#### EKU.DOCUMENT_SIGNING

> `readonly` **DOCUMENT_SIGNING**: `"1.3.6.1.4.1.311.10.3.12"` = `'1.3.6.1.4.1.311.10.3.12'`

Document Signing (Microsoft)

#### EKU.EMAIL_PROTECTION

> `readonly` **EMAIL_PROTECTION**: `"1.3.6.1.5.5.7.3.4"` = `'1.3.6.1.5.5.7.3.4'`

Email Protection

#### EKU.OCSP_SIGNING

> `readonly` **OCSP_SIGNING**: `"1.3.6.1.5.5.7.3.9"` = `'1.3.6.1.5.5.7.3.9'`

OCSP Signing

#### EKU.SERVER_AUTH

> `readonly` **SERVER_AUTH**: `"1.3.6.1.5.5.7.3.1"` = `'1.3.6.1.5.5.7.3.1'`

TLS Web Server Authentication

#### EKU.TIME_STAMPING

> `readonly` **TIME_STAMPING**: `"1.3.6.1.5.5.7.3.8"` = `'1.3.6.1.5.5.7.3.8'`

Time Stamping

### ENCRYPTION

> `readonly` **ENCRYPTION**: `object`

Symmetric Encryption Algorithms

#### ENCRYPTION.AES_128_CBC

> `readonly` **AES_128_CBC**: `"2.16.840.1.101.3.4.1.2"` = `'2.16.840.1.101.3.4.1.2'`

AES-128 in CBC mode

#### ENCRYPTION.AES_128_CCM

> `readonly` **AES_128_CCM**: `"2.16.840.1.101.3.4.1.7"` = `'2.16.840.1.101.3.4.1.7'`

AES-128 in CCM mode

#### ENCRYPTION.AES_128_ECB

> `readonly` **AES_128_ECB**: `"2.16.840.1.101.3.4.1.1"` = `'2.16.840.1.101.3.4.1.1'`

AES-128 in ECB mode

#### ENCRYPTION.AES_128_GCM

> `readonly` **AES_128_GCM**: `"2.16.840.1.101.3.4.1.6"` = `'2.16.840.1.101.3.4.1.6'`

AES-128 in GCM mode

#### ENCRYPTION.AES_192_CBC

> `readonly` **AES_192_CBC**: `"2.16.840.1.101.3.4.1.22"` = `'2.16.840.1.101.3.4.1.22'`

AES-192 in CBC mode

#### ENCRYPTION.AES_192_CCM

> `readonly` **AES_192_CCM**: `"2.16.840.1.101.3.4.1.27"` = `'2.16.840.1.101.3.4.1.27'`

AES-192 in CCM mode

#### ENCRYPTION.AES_192_ECB

> `readonly` **AES_192_ECB**: `"2.16.840.1.101.3.4.1.21"` = `'2.16.840.1.101.3.4.1.21'`

AES-192 in ECB mode

#### ENCRYPTION.AES_192_GCM

> `readonly` **AES_192_GCM**: `"2.16.840.1.101.3.4.1.26"` = `'2.16.840.1.101.3.4.1.26'`

AES-192 in GCM mode

#### ENCRYPTION.AES_256_CBC

> `readonly` **AES_256_CBC**: `"2.16.840.1.101.3.4.1.42"` = `'2.16.840.1.101.3.4.1.42'`

AES-256 in CBC mode

#### ENCRYPTION.AES_256_CCM

> `readonly` **AES_256_CCM**: `"2.16.840.1.101.3.4.1.47"` = `'2.16.840.1.101.3.4.1.47'`

AES-256 in CCM mode

#### ENCRYPTION.AES_256_ECB

> `readonly` **AES_256_ECB**: `"2.16.840.1.101.3.4.1.41"` = `'2.16.840.1.101.3.4.1.41'`

AES-256 in ECB mode

#### ENCRYPTION.AES_256_GCM

> `readonly` **AES_256_GCM**: `"2.16.840.1.101.3.4.1.46"` = `'2.16.840.1.101.3.4.1.46'`

AES-256 in GCM mode

#### ENCRYPTION.DES_EDE3_CBC

> `readonly` **DES_EDE3_CBC**: `"1.2.840.113549.3.7"` = `'1.2.840.113549.3.7'`

Triple DES in CBC mode

### EXTENSION

> `readonly` **EXTENSION**: `object`

X.509 Certificate Extensions

#### EXTENSION.AUTHORITY_INFO_ACCESS

> `readonly` **AUTHORITY_INFO_ACCESS**: `"1.3.6.1.5.5.7.1.1"` = `'1.3.6.1.5.5.7.1.1'`

Authority Information Access

#### EXTENSION.AUTHORITY_KEY_IDENTIFIER

> `readonly` **AUTHORITY_KEY_IDENTIFIER**: `"2.5.29.35"` = `'2.5.29.35'`

Authority Key Identifier

#### EXTENSION.BASIC_CONSTRAINTS

> `readonly` **BASIC_CONSTRAINTS**: `"2.5.29.19"` = `'2.5.29.19'`

Basic Constraints

#### EXTENSION.CERTIFICATE_POLICIES

> `readonly` **CERTIFICATE_POLICIES**: `"2.5.29.32"` = `'2.5.29.32'`

Certificate Policies

#### EXTENSION.CRL_DISTRIBUTION_POINTS

> `readonly` **CRL_DISTRIBUTION_POINTS**: `"2.5.29.31"` = `'2.5.29.31'`

CRL Distribution Points

#### EXTENSION.CRL_NUMBER

> `readonly` **CRL_NUMBER**: `"2.5.29.20"` = `'2.5.29.20'`

CRL Number

#### EXTENSION.CRL_REASON_CODE

> `readonly` **CRL_REASON_CODE**: `"2.5.29.21"` = `'2.5.29.21'`

CRL Reason Code

#### EXTENSION.EXTENDED_KEY_USAGE

> `readonly` **EXTENDED_KEY_USAGE**: `"2.5.29.37"` = `'2.5.29.37'`

Extended Key Usage

#### EXTENSION.KEY_USAGE

> `readonly` **KEY_USAGE**: `"2.5.29.15"` = `'2.5.29.15'`

Key Usage

#### EXTENSION.SUBJECT_ALT_NAME

> `readonly` **SUBJECT_ALT_NAME**: `"2.5.29.17"` = `'2.5.29.17'`

Subject Alternative Name

#### EXTENSION.SUBJECT_KEY_IDENTIFIER

> `readonly` **SUBJECT_KEY_IDENTIFIER**: `"2.5.29.14"` = `'2.5.29.14'`

Subject Key Identifier

### getOidFriendlyName()

> **getOidFriendlyName**: (`oid`) => `string`

Get a friendly name for an OID

#### Parameters

##### oid

`string`

The OID to get a friendly name for

#### Returns

`string`

The friendly name if available, otherwise the OID itself

### HASH

> `readonly` **HASH**: `object`

Hash Functions

#### HASH.HMAC_SHA1

> `readonly` **HMAC_SHA1**: `"1.2.840.113549.2.7"` = `'1.2.840.113549.2.7'`

HMAC with SHA-1

#### HASH.HMAC_SHA256

> `readonly` **HMAC_SHA256**: `"1.2.840.113549.2.9"` = `'1.2.840.113549.2.9'`

HMAC with SHA-256

#### HASH.HMAC_SHA384

> `readonly` **HMAC_SHA384**: `"1.2.840.113549.2.10"` = `'1.2.840.113549.2.10'`

HMAC with SHA-384

#### HASH.HMAC_SHA512

> `readonly` **HMAC_SHA512**: `"1.2.840.113549.2.11"` = `'1.2.840.113549.2.11'`

HMAC with SHA-512

#### HASH.MD5

> `readonly` **MD5**: `"1.2.840.113549.2.5"` = `'1.2.840.113549.2.5'`

MD5 Hash

#### HASH.SHA1

> `readonly` **SHA1**: `"1.3.14.3.2.26"` = `'1.3.14.3.2.26'`

SHA-1 Hash

#### HASH.SHA256

> `readonly` **SHA256**: `"2.16.840.1.101.3.4.2.1"` = `'2.16.840.1.101.3.4.2.1'`

SHA-256 Hash

#### HASH.SHA384

> `readonly` **SHA384**: `"2.16.840.1.101.3.4.2.2"` = `'2.16.840.1.101.3.4.2.2'`

SHA-384 Hash

#### HASH.SHA512

> `readonly` **SHA512**: `"2.16.840.1.101.3.4.2.3"` = `'2.16.840.1.101.3.4.2.3'`

SHA-512 Hash

### OTHER_REV_INFO

> `readonly` **OTHER_REV_INFO**: `object`

OTHER_REV_INFO

#### OTHER_REV_INFO.OCSP

> `readonly` **OCSP**: `"1.3.6.1.5.5.7.16.2"` = `'1.3.6.1.5.5.7.16.2'`

OCSP

### PKCS12

> `readonly` **PKCS12**: `object`

PKCS#12 OIDs

#### PKCS12.BAGS

> `readonly` **BAGS**: `object`

Bag types under pkcs-12PbeIds

#### PKCS12.BAGS.CERT_BAG

> `readonly` **CERT_BAG**: `"1.2.840.113549.1.12.10.1.3"` = `'1.2.840.113549.1.12.10.1.3'`

certBag

#### PKCS12.BAGS.CRL_BAG

> `readonly` **CRL_BAG**: `"1.2.840.113549.1.12.10.1.4"` = `'1.2.840.113549.1.12.10.1.4'`

crlBag

#### PKCS12.BAGS.KEY_BAG

> `readonly` **KEY_BAG**: `"1.2.840.113549.1.12.10.1.1"` = `'1.2.840.113549.1.12.10.1.1'`

keyBag

#### PKCS12.BAGS.PKCS8_SHROUDED_KEY_BAG

> `readonly` **PKCS8_SHROUDED_KEY_BAG**: `"1.2.840.113549.1.12.10.1.2"` = `'1.2.840.113549.1.12.10.1.2'`

pkcs8ShroudedKeyBag

#### PKCS12.BAGS.SAFE_CONTENTS_BAG

> `readonly` **SAFE_CONTENTS_BAG**: `"1.2.840.113549.1.12.10.1.6"` = `'1.2.840.113549.1.12.10.1.6'`

safeContentsBag

#### PKCS12.BAGS.SECRET_BAG

> `readonly` **SECRET_BAG**: `"1.2.840.113549.1.12.10.1.5"` = `'1.2.840.113549.1.12.10.1.5'`

secretBag

#### PKCS12.CERT_TYPES

> `readonly` **CERT_TYPES**: `object`

Certificate types inside CertBag

#### PKCS12.CERT_TYPES.SDSI_CERT

> `readonly` **SDSI_CERT**: `"1.2.840.113549.1.9.22.2"` = `'1.2.840.113549.1.9.22.2'`

sdsiCertificate

#### PKCS12.CERT_TYPES.X509_CERT

> `readonly` **X509_CERT**: `"1.2.840.113549.1.9.22.1"` = `'1.2.840.113549.1.9.22.1'`

x509Certificate

#### PKCS12.PBE

> `readonly` **PBE**: `object`

Password-based encryption schemes (pkcs-12PbeIds)

#### PKCS12.PBE.SHA1_3DES_2KEY_CBC

> `readonly` **SHA1_3DES_2KEY_CBC**: `"1.2.840.113549.1.12.1.4"` = `'1.2.840.113549.1.12.1.4'`

pbeWithSHAAnd2-KeyTripleDES-CBC

#### PKCS12.PBE.SHA1_3DES_3KEY_CBC

> `readonly` **SHA1_3DES_3KEY_CBC**: `"1.2.840.113549.1.12.1.3"` = `'1.2.840.113549.1.12.1.3'`

pbeWithSHAAnd3-KeyTripleDES-CBC

#### PKCS12.PBE.SHA1_RC2_128_CBC

> `readonly` **SHA1_RC2_128_CBC**: `"1.2.840.113549.1.12.1.5"` = `'1.2.840.113549.1.12.1.5'`

pbeWithSHAAnd128BitRC2-CBC

#### PKCS12.PBE.SHA1_RC2_40_CBC

> `readonly` **SHA1_RC2_40_CBC**: `"1.2.840.113549.1.12.1.6"` = `'1.2.840.113549.1.12.1.6'`

pbeWithSHAAnd40BitRC2-CBC

#### PKCS12.PBE.SHA1_RC4_128

> `readonly` **SHA1_RC4_128**: `"1.2.840.113549.1.12.1.1"` = `'1.2.840.113549.1.12.1.1'`

pbeWithSHAAnd128BitRC4

#### PKCS12.PBE.SHA1_RC4_40

> `readonly` **SHA1_RC4_40**: `"1.2.840.113549.1.12.1.2"` = `'1.2.840.113549.1.12.1.2'`

pbeWithSHAAnd40BitRC4

### PKCS5

> `readonly` **PKCS5**: `object`

PKCS#5 OIDs

#### PKCS5.PBES2

> `readonly` **PBES2**: `"1.2.840.113549.1.5.13"` = `'1.2.840.113549.1.5.13'`

Password-Based Encryption Scheme 2

#### PKCS5.PBKDF2

> `readonly` **PBKDF2**: `"1.2.840.113549.1.5.12"` = `'1.2.840.113549.1.5.12'`

PBKDF2 Key Derivation Function

### PKCS7

> `readonly` **PKCS7**: `object`

PKCS#7/CMS Content Types

#### PKCS7.AUTH_ENVELOPED_DATA

> `readonly` **AUTH_ENVELOPED_DATA**: `"1.2.840.113549.1.9.16.1.23"` = `'1.2.840.113549.1.9.16.1.23'`

AuthEnvelopedData content type

#### PKCS7.AUTHENTICATED_DATA

> `readonly` **AUTHENTICATED_DATA**: `"1.2.840.113549.1.7.7"` = `'1.2.840.113549.1.7.7'`

AuthenticatedData content type

#### PKCS7.DATA

> `readonly` **DATA**: `"1.2.840.113549.1.7.1"` = `'1.2.840.113549.1.7.1'`

Data content type

#### PKCS7.DIGESTED_DATA

> `readonly` **DIGESTED_DATA**: `"1.2.840.113549.1.7.5"` = `'1.2.840.113549.1.7.5'`

DigestedData content type

#### PKCS7.ENCRYPTED_DATA

> `readonly` **ENCRYPTED_DATA**: `"1.2.840.113549.1.7.6"` = `'1.2.840.113549.1.7.6'`

EncryptedData content type

#### PKCS7.ENVELOPED_DATA

> `readonly` **ENVELOPED_DATA**: `"1.2.840.113549.1.7.3"` = `'1.2.840.113549.1.7.3'`

EnvelopedData content type

#### PKCS7.SIGNED_AND_ENVELOPED_DATA

> `readonly` **SIGNED_AND_ENVELOPED_DATA**: `"1.2.840.113549.1.7.4"` = `'1.2.840.113549.1.7.4'`

SignedAndEnvelopedData content type

#### PKCS7.SIGNED_DATA

> `readonly` **SIGNED_DATA**: `"1.2.840.113549.1.7.2"` = `'1.2.840.113549.1.7.2'`

SignedData content type

#### PKCS7.TST_INFO

> `readonly` **TST_INFO**: `"1.2.840.113549.1.9.16.1.4"` = `'1.2.840.113549.1.9.16.1.4'`

TSTInfo content type (RFC 3161)

### PKCS9

> `readonly` **PKCS9**: `object`

PKCS#9 Attributes

#### PKCS9.CHALLENGE_PASSWORD

> `readonly` **CHALLENGE_PASSWORD**: `"1.2.840.113549.1.9.7"` = `'1.2.840.113549.1.9.7'`

Challenge Password

#### PKCS9.CONTENT_TYPE

> `readonly` **CONTENT_TYPE**: `"1.2.840.113549.1.9.3"` = `'1.2.840.113549.1.9.3'`

Content Type

#### PKCS9.EMAIL_ADDRESS

> `readonly` **EMAIL_ADDRESS**: `"1.2.840.113549.1.9.1"` = `'1.2.840.113549.1.9.1'`

Email Address

#### PKCS9.ETS_COMMITMENT_TYPE_INDICATION

> `readonly` **ETS_COMMITMENT_TYPE_INDICATION**: `"1.2.840.113549.1.9.16.2.16"` = `'1.2.840.113549.1.9.16.2.16'`

Commitment Type Indication

#### PKCS9.ETS_REVOCATION_VALUES

> `readonly` **ETS_REVOCATION_VALUES**: `"1.2.840.113549.1.9.16.2.24"` = `'1.2.840.113549.1.9.16.2.24'`

Revocation Values

#### PKCS9.ETS_SIGNATURE_POLICY_IDENTIFIER

> `readonly` **ETS_SIGNATURE_POLICY_IDENTIFIER**: `"1.2.840.113549.1.9.16.2.15"` = `'1.2.840.113549.1.9.16.2.15'`

Signature Policy Identifier

#### PKCS9.ETS_SIGNING_CERTIFICATE

> `readonly` **ETS_SIGNING_CERTIFICATE**: `"1.2.840.113549.1.9.16.2.12"` = `'1.2.840.113549.1.9.16.2.12'`

Signing Certificate

#### PKCS9.ETS_SIGNING_CERTIFICATE_V2

> `readonly` **ETS_SIGNING_CERTIFICATE_V2**: `"1.2.840.113549.1.9.16.2.47"` = `'1.2.840.113549.1.9.16.2.47'`

Signing Certificate V2

#### PKCS9.ETS_SIGNING_LOCATION

> `readonly` **ETS_SIGNING_LOCATION**: `"1.2.840.113549.1.9.16.2.17"` = `'1.2.840.113549.1.9.16.2.17'`

Signing Location

#### PKCS9.EXTENSION_REQUEST

> `readonly` **EXTENSION_REQUEST**: `"1.2.840.113549.1.9.14"` = `'1.2.840.113549.1.9.14'`

Extension Request

#### PKCS9.FRIENDLY_NAME

> `readonly` **FRIENDLY_NAME**: `"1.2.840.113549.1.9.20"` = `'1.2.840.113549.1.9.20'`

Friendly Name

#### PKCS9.MESSAGE_DIGEST

> `readonly` **MESSAGE_DIGEST**: `"1.2.840.113549.1.9.4"` = `'1.2.840.113549.1.9.4'`

Message Digest

#### PKCS9.SIGNING_TIME

> `readonly` **SIGNING_TIME**: `"1.2.840.113549.1.9.5"` = `'1.2.840.113549.1.9.5'`

Signing Time

#### PKCS9.TIME_STAMP_TOKEN

> `readonly` **TIME_STAMP_TOKEN**: `"1.2.840.113549.1.9.16.2.14"` = `'1.2.840.113549.1.9.16.2.14'`

Time Stamp Token

### PKIX

> `readonly` **PKIX**: `object`

PKIX (Public Key Infrastructure X.509)

#### PKIX.ID_PKIX_OCSP_BASIC

> `readonly` **ID_PKIX_OCSP_BASIC**: `"1.3.6.1.5.5.7.48.1.1"` = `'1.3.6.1.5.5.7.48.1.1'`

OCSP Basic Response

#### PKIX.ID_PKIX_OCSP_NONCE

> `readonly` **ID_PKIX_OCSP_NONCE**: `"1.3.6.1.5.5.7.48.1.2"` = `'1.3.6.1.5.5.7.48.1.2'`

OCSP Nonce Extension

### RSA

> `readonly` **RSA**: `object`

RSA Algorithms

#### RSA.ENCRYPTION

> `readonly` **ENCRYPTION**: `"1.2.840.113549.1.1.1"` = `'1.2.840.113549.1.1.1'`

RSA Encryption

#### RSA.MD2_WITH_RSA

> `readonly` **MD2_WITH_RSA**: `"1.2.840.113549.1.1.2"` = `'1.2.840.113549.1.1.2'`

MD2 with RSA Signature

#### RSA.MD5_WITH_RSA

> `readonly` **MD5_WITH_RSA**: `"1.2.840.113549.1.1.4"` = `'1.2.840.113549.1.1.4'`

MD5 with RSA Signature

#### RSA.MGF1

> `readonly` **MGF1**: `"1.2.840.113549.1.1.8"` = `'1.2.840.113549.1.1.8'`

Mask Generation Function 1

#### RSA.PSPECIFIED

> `readonly` **PSPECIFIED**: `"1.2.840.113549.1.1.9"` = `'1.2.840.113549.1.1.9'`

P Source specified directly (id-pSpecified)

#### RSA.RSAES_OAEP

> `readonly` **RSAES_OAEP**: `"1.2.840.113549.1.1.7"` = `'1.2.840.113549.1.1.7'`

RSAES-OAEP Key Transport

#### RSA.RSASSA_PSS

> `readonly` **RSASSA_PSS**: `"1.2.840.113549.1.1.10"` = `'1.2.840.113549.1.1.10'`

RSASSA-PSS Signature

#### RSA.SHA1_WITH_RSA

> `readonly` **SHA1_WITH_RSA**: `"1.2.840.113549.1.1.5"` = `'1.2.840.113549.1.1.5'`

SHA-1 with RSA Signature

#### RSA.SHA256_WITH_RSA

> `readonly` **SHA256_WITH_RSA**: `"1.2.840.113549.1.1.11"` = `'1.2.840.113549.1.1.11'`

SHA-256 with RSA Signature

#### RSA.SHA384_WITH_RSA

> `readonly` **SHA384_WITH_RSA**: `"1.2.840.113549.1.1.12"` = `'1.2.840.113549.1.1.12'`

SHA-384 with RSA Signature

#### RSA.SHA512_WITH_RSA

> `readonly` **SHA512_WITH_RSA**: `"1.2.840.113549.1.1.13"` = `'1.2.840.113549.1.1.13'`

SHA-512 with RSA Signature
