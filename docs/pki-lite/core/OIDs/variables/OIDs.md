[**PKI-Lite**](../../../../README.md)

---

[PKI-Lite](../../../../README.md) / [pki-lite](../../../README.md) / [core/OIDs](../README.md) / OIDs

# Variable: OIDs

> `const` **OIDs**: `object`

Object Identifiers (OIDs) for cryptographic algorithms, data formats, and PKI standards.

## Type Declaration

### ADOBE

> **ADOBE**: `object`

Adobe OIDs

#### ADOBE.REVOCATION_INFO_ARCHIVAL

> **REVOCATION_INFO_ARCHIVAL**: `string` = `'1.2.840.113583.1.1.8'`

Revocation Info Archival

### AUTHORITY_INFO_ACCESS

> **AUTHORITY_INFO_ACCESS**: `object`

AUTHORITY_INFO_ACCESS extension access methods

#### AUTHORITY_INFO_ACCESS.CA_ISSUERS

> **CA_ISSUERS**: `string` = `'1.3.6.1.5.5.7.48.2'`

CA Issuers

#### AUTHORITY_INFO_ACCESS.OCSP

> **OCSP**: `string` = `'1.3.6.1.5.5.7.48.1'`

OCSP

### CURVES

> **CURVES**: `object`

Named Elliptic Curves

#### CURVES.ED25519

> **ED25519**: `string` = `'1.3.101.112'`

Ed25519 curve for EdDSA

#### CURVES.ED448

> **ED448**: `string` = `'1.3.101.113'`

Ed448 curve for EdDSA

#### CURVES.SECP256K1

> **SECP256K1**: `string` = `'1.3.132.0.10'`

secp256k1 (used in Bitcoin and other cryptocurrencies)

#### CURVES.SECP256R1

> **SECP256R1**: `string` = `'1.2.840.10045.3.1.7'`

NIST P-256 / secp256r1

#### CURVES.SECP384R1

> **SECP384R1**: `string` = `'1.3.132.0.34'`

NIST P-384 / secp384r1

#### CURVES.SECP521R1

> **SECP521R1**: `string` = `'1.3.132.0.35'`

NIST P-521 / secp521r1

#### CURVES.X25519

> **X25519**: `string` = `'1.3.101.110'`

X25519 curve for ECDH

#### CURVES.X448

> **X448**: `string` = `'1.3.101.111'`

X448 curve for ECDH

### DN

> **DN**: `object`

Distinguished Name (DN) components

#### DN.C

> **C**: `string` = `'2.5.4.6'`

Country

#### DN.CN

> **CN**: `string` = `'2.5.4.3'`

Common Name

#### DN.EMAIL

> **EMAIL**: `string` = `'1.2.840.113549.1.9.1'`

Email Address (PKCS#9)

#### DN.L

> **L**: `string` = `'2.5.4.7'`

Locality

#### DN.O

> **O**: `string` = `'2.5.4.10'`

Organization

#### DN.OU

> **OU**: `string` = `'2.5.4.11'`

Organizational Unit

#### DN.ST

> **ST**: `string` = `'2.5.4.8'`

State or Province

### DSA

> **DSA**: `object`

DSA Algorithms

#### DSA.ALGORITHM

> **ALGORITHM**: `string` = `'1.2.840.10040.4.1'`

Digital Signature Algorithm

#### DSA.SHA1_WITH_DSA

> **SHA1_WITH_DSA**: `string` = `'1.2.840.10040.4.3'`

SHA-1 with DSA Signature

#### DSA.SHA256_WITH_DSA

> **SHA256_WITH_DSA**: `string` = `'2.16.840.1.101.3.4.3.2'`

SHA-256 with DSA Signature

### EC

> **EC**: `object`

Elliptic Curve Cryptography

#### EC.ECDH

> **ECDH**: `string` = `'1.2.840.10045.3.1.1'`

Elliptic Curve Diffie-Hellman (ECDH)

#### EC.PUBLIC_KEY

> **PUBLIC_KEY**: `string` = `'1.2.840.10045.2.1'`

Elliptic Curve Public Key

#### EC.SHA1_WITH_ECDSA

> **SHA1_WITH_ECDSA**: `string` = `'1.2.840.10045.4.1'`

SHA-1 with ECDSA Signature

#### EC.SHA256_WITH_ECDSA

> **SHA256_WITH_ECDSA**: `string` = `'1.2.840.10045.4.3.2'`

SHA-256 with ECDSA Signature

#### EC.SHA384_WITH_ECDSA

> **SHA384_WITH_ECDSA**: `string` = `'1.2.840.10045.4.3.3'`

SHA-384 with ECDSA Signature

#### EC.SHA512_WITH_ECDSA

> **SHA512_WITH_ECDSA**: `string` = `'1.2.840.10045.4.3.4'`

SHA-512 with ECDSA Signature

### EKU

> **EKU**: `object`

Extended Key Usage Purpose OIDs

#### EKU.CLIENT_AUTH

> **CLIENT_AUTH**: `string` = `'1.3.6.1.5.5.7.3.2'`

TLS Web Client Authentication

#### EKU.CODE_SIGNING

> **CODE_SIGNING**: `string` = `'1.3.6.1.5.5.7.3.3'`

Code Signing

#### EKU.DOCUMENT_SIGNING

> **DOCUMENT_SIGNING**: `string` = `'1.3.6.1.4.1.311.10.3.12'`

Document Signing (Microsoft)

#### EKU.EMAIL_PROTECTION

> **EMAIL_PROTECTION**: `string` = `'1.3.6.1.5.5.7.3.4'`

Email Protection

#### EKU.OCSP_SIGNING

> **OCSP_SIGNING**: `string` = `'1.3.6.1.5.5.7.3.9'`

OCSP Signing

#### EKU.SERVER_AUTH

> **SERVER_AUTH**: `string` = `'1.3.6.1.5.5.7.3.1'`

TLS Web Server Authentication

#### EKU.TIME_STAMPING

> **TIME_STAMPING**: `string` = `'1.3.6.1.5.5.7.3.8'`

Time Stamping

### ENCRYPTION

> **ENCRYPTION**: `object`

Symmetric Encryption Algorithms

#### ENCRYPTION.AES_128_CBC

> **AES_128_CBC**: `string` = `'2.16.840.1.101.3.4.1.2'`

AES-128 in CBC mode

#### ENCRYPTION.AES_128_CCM

> **AES_128_CCM**: `string` = `'2.16.840.1.101.3.4.1.7'`

AES-128 in CCM mode

#### ENCRYPTION.AES_128_ECB

> **AES_128_ECB**: `string` = `'2.16.840.1.101.3.4.1.1'`

AES-128 in ECB mode

#### ENCRYPTION.AES_128_GCM

> **AES_128_GCM**: `string` = `'2.16.840.1.101.3.4.1.6'`

AES-128 in GCM mode

#### ENCRYPTION.AES_192_CBC

> **AES_192_CBC**: `string` = `'2.16.840.1.101.3.4.1.22'`

AES-192 in CBC mode

#### ENCRYPTION.AES_192_CCM

> **AES_192_CCM**: `string` = `'2.16.840.1.101.3.4.1.27'`

AES-192 in CCM mode

#### ENCRYPTION.AES_192_ECB

> **AES_192_ECB**: `string` = `'2.16.840.1.101.3.4.1.21'`

AES-192 in ECB mode

#### ENCRYPTION.AES_192_GCM

> **AES_192_GCM**: `string` = `'2.16.840.1.101.3.4.1.26'`

AES-192 in GCM mode

#### ENCRYPTION.AES_256_CBC

> **AES_256_CBC**: `string` = `'2.16.840.1.101.3.4.1.42'`

AES-256 in CBC mode

#### ENCRYPTION.AES_256_CCM

> **AES_256_CCM**: `string` = `'2.16.840.1.101.3.4.1.47'`

AES-256 in CCM mode

#### ENCRYPTION.AES_256_ECB

> **AES_256_ECB**: `string` = `'2.16.840.1.101.3.4.1.41'`

AES-256 in ECB mode

#### ENCRYPTION.AES_256_GCM

> **AES_256_GCM**: `string` = `'2.16.840.1.101.3.4.1.46'`

AES-256 in GCM mode

#### ENCRYPTION.DES_EDE3_CBC

> **DES_EDE3_CBC**: `string` = `'1.2.840.113549.3.7'`

Triple DES in CBC mode

### EXTENSION

> **EXTENSION**: `object`

X.509 Certificate Extensions

#### EXTENSION.AUTHORITY_INFO_ACCESS

> **AUTHORITY_INFO_ACCESS**: `string` = `'1.3.6.1.5.5.7.1.1'`

Authority Information Access

#### EXTENSION.AUTHORITY_KEY_IDENTIFIER

> **AUTHORITY_KEY_IDENTIFIER**: `string` = `'2.5.29.35'`

Authority Key Identifier

#### EXTENSION.BASIC_CONSTRAINTS

> **BASIC_CONSTRAINTS**: `string` = `'2.5.29.19'`

Basic Constraints

#### EXTENSION.CERTIFICATE_POLICIES

> **CERTIFICATE_POLICIES**: `string` = `'2.5.29.32'`

Certificate Policies

#### EXTENSION.CRL_DISTRIBUTION_POINTS

> **CRL_DISTRIBUTION_POINTS**: `string` = `'2.5.29.31'`

CRL Distribution Points

#### EXTENSION.CRL_NUMBER

> **CRL_NUMBER**: `string` = `'2.5.29.20'`

CRL Number

#### EXTENSION.CRL_REASON_CODE

> **CRL_REASON_CODE**: `string` = `'2.5.29.21'`

CRL Reason Code

#### EXTENSION.EXTENDED_KEY_USAGE

> **EXTENDED_KEY_USAGE**: `string` = `'2.5.29.37'`

Extended Key Usage

#### EXTENSION.KEY_USAGE

> **KEY_USAGE**: `string` = `'2.5.29.15'`

Key Usage

#### EXTENSION.SUBJECT_ALT_NAME

> **SUBJECT_ALT_NAME**: `string` = `'2.5.29.17'`

Subject Alternative Name

#### EXTENSION.SUBJECT_KEY_IDENTIFIER

> **SUBJECT_KEY_IDENTIFIER**: `string` = `'2.5.29.14'`

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

> **HASH**: `object`

Hash Functions

#### HASH.HMAC_SHA1

> **HMAC_SHA1**: `string` = `'1.2.840.113549.2.7'`

HMAC with SHA-1

#### HASH.HMAC_SHA256

> **HMAC_SHA256**: `string` = `'1.2.840.113549.2.9'`

HMAC with SHA-256

#### HASH.HMAC_SHA384

> **HMAC_SHA384**: `string` = `'1.2.840.113549.2.10'`

HMAC with SHA-384

#### HASH.HMAC_SHA512

> **HMAC_SHA512**: `string` = `'1.2.840.113549.2.11'`

HMAC with SHA-512

#### HASH.MD5

> **MD5**: `string` = `'1.2.840.113549.2.5'`

MD5 Hash

#### HASH.SHA1

> **SHA1**: `string` = `'1.3.14.3.2.26'`

SHA-1 Hash

#### HASH.SHA256

> **SHA256**: `string` = `'2.16.840.1.101.3.4.2.1'`

SHA-256 Hash

#### HASH.SHA384

> **SHA384**: `string` = `'2.16.840.1.101.3.4.2.2'`

SHA-384 Hash

#### HASH.SHA512

> **SHA512**: `string` = `'2.16.840.1.101.3.4.2.3'`

SHA-512 Hash

### OTHER_REV_INFO

> **OTHER_REV_INFO**: `object`

OTHER_REV_INFO

#### OTHER_REV_INFO.OCSP

> **OCSP**: `string` = `'1.3.6.1.5.5.7.16.2'`

OCSP

### PKCS12

> **PKCS12**: `object`

PKCS#12 OIDs

#### PKCS12.BAGS

> **BAGS**: `object`

Bag types under pkcs-12PbeIds

#### PKCS12.BAGS.CERT_BAG

> **CERT_BAG**: `string` = `'1.2.840.113549.1.12.10.1.3'`

certBag

#### PKCS12.BAGS.CRL_BAG

> **CRL_BAG**: `string` = `'1.2.840.113549.1.12.10.1.4'`

crlBag

#### PKCS12.BAGS.KEY_BAG

> **KEY_BAG**: `string` = `'1.2.840.113549.1.12.10.1.1'`

keyBag

#### PKCS12.BAGS.PKCS8_SHROUDED_KEY_BAG

> **PKCS8_SHROUDED_KEY_BAG**: `string` = `'1.2.840.113549.1.12.10.1.2'`

pkcs8ShroudedKeyBag

#### PKCS12.BAGS.SAFE_CONTENTS_BAG

> **SAFE_CONTENTS_BAG**: `string` = `'1.2.840.113549.1.12.10.1.6'`

safeContentsBag

#### PKCS12.BAGS.SECRET_BAG

> **SECRET_BAG**: `string` = `'1.2.840.113549.1.12.10.1.5'`

secretBag

#### PKCS12.CERT_TYPES

> **CERT_TYPES**: `object`

Certificate types inside CertBag

#### PKCS12.CERT_TYPES.SDSI_CERT

> **SDSI_CERT**: `string` = `'1.2.840.113549.1.9.22.2'`

sdsiCertificate

#### PKCS12.CERT_TYPES.X509_CERT

> **X509_CERT**: `string` = `'1.2.840.113549.1.9.22.1'`

x509Certificate

#### PKCS12.PBE

> **PBE**: `object`

Password-based encryption schemes (pkcs-12PbeIds)

#### PKCS12.PBE.SHA1_3DES_2KEY_CBC

> **SHA1_3DES_2KEY_CBC**: `string` = `'1.2.840.113549.1.12.1.4'`

pbeWithSHAAnd2-KeyTripleDES-CBC

#### PKCS12.PBE.SHA1_3DES_3KEY_CBC

> **SHA1_3DES_3KEY_CBC**: `string` = `'1.2.840.113549.1.12.1.3'`

pbeWithSHAAnd3-KeyTripleDES-CBC

#### PKCS12.PBE.SHA1_RC2_128_CBC

> **SHA1_RC2_128_CBC**: `string` = `'1.2.840.113549.1.12.1.5'`

pbeWithSHAAnd128BitRC2-CBC

#### PKCS12.PBE.SHA1_RC2_40_CBC

> **SHA1_RC2_40_CBC**: `string` = `'1.2.840.113549.1.12.1.6'`

pbeWithSHAAnd40BitRC2-CBC

#### PKCS12.PBE.SHA1_RC4_128

> **SHA1_RC4_128**: `string` = `'1.2.840.113549.1.12.1.1'`

pbeWithSHAAnd128BitRC4

#### PKCS12.PBE.SHA1_RC4_40

> **SHA1_RC4_40**: `string` = `'1.2.840.113549.1.12.1.2'`

pbeWithSHAAnd40BitRC4

### PKCS5

> **PKCS5**: `object`

PKCS#5 OIDs

#### PKCS5.PBES2

> **PBES2**: `string` = `'1.2.840.113549.1.5.13'`

Password-Based Encryption Scheme 2

#### PKCS5.PBKDF2

> **PBKDF2**: `string` = `'1.2.840.113549.1.5.12'`

PBKDF2 Key Derivation Function

### PKCS7

> **PKCS7**: `object`

PKCS#7/CMS Content Types

#### PKCS7.AUTH_ENVELOPED_DATA

> **AUTH_ENVELOPED_DATA**: `string` = `'1.2.840.113549.1.9.16.1.23'`

AuthEnvelopedData content type

#### PKCS7.AUTHENTICATED_DATA

> **AUTHENTICATED_DATA**: `string` = `'1.2.840.113549.1.7.7'`

AuthenticatedData content type

#### PKCS7.DATA

> **DATA**: `string` = `'1.2.840.113549.1.7.1'`

Data content type

#### PKCS7.DIGESTED_DATA

> **DIGESTED_DATA**: `string` = `'1.2.840.113549.1.7.5'`

DigestedData content type

#### PKCS7.ENCRYPTED_DATA

> **ENCRYPTED_DATA**: `string` = `'1.2.840.113549.1.7.6'`

EncryptedData content type

#### PKCS7.ENVELOPED_DATA

> **ENVELOPED_DATA**: `string` = `'1.2.840.113549.1.7.3'`

EnvelopedData content type

#### PKCS7.SIGNED_AND_ENVELOPED_DATA

> **SIGNED_AND_ENVELOPED_DATA**: `string` = `'1.2.840.113549.1.7.4'`

SignedAndEnvelopedData content type

#### PKCS7.SIGNED_DATA

> **SIGNED_DATA**: `string` = `'1.2.840.113549.1.7.2'`

SignedData content type

### PKCS9

> **PKCS9**: `object`

PKCS#9 Attributes

#### PKCS9.CHALLENGE_PASSWORD

> **CHALLENGE_PASSWORD**: `string` = `'1.2.840.113549.1.9.7'`

Challenge Password

#### PKCS9.CONTENT_TYPE

> **CONTENT_TYPE**: `string` = `'1.2.840.113549.1.9.3'`

Content Type

#### PKCS9.EMAIL_ADDRESS

> **EMAIL_ADDRESS**: `string` = `'1.2.840.113549.1.9.1'`

Email Address

#### PKCS9.ETS_COMMITMENT_TYPE_INDICATION

> **ETS_COMMITMENT_TYPE_INDICATION**: `string` = `'1.2.840.113549.1.9.16.2.16'`

Commitment Type Indication

#### PKCS9.ETS_REVOCATION_VALUES

> **ETS_REVOCATION_VALUES**: `string` = `'1.2.840.113549.1.9.16.2.24'`

Revocation Values

#### PKCS9.ETS_SIGNATURE_POLICY_IDENTIFIER

> **ETS_SIGNATURE_POLICY_IDENTIFIER**: `string` = `'1.2.840.113549.1.9.16.2.15'`

Signature Policy Identifier

#### PKCS9.ETS_SIGNING_CERTIFICATE

> **ETS_SIGNING_CERTIFICATE**: `string` = `'1.2.840.113549.1.9.16.2.12'`

Signing Certificate

#### PKCS9.ETS_SIGNING_CERTIFICATE_V2

> **ETS_SIGNING_CERTIFICATE_V2**: `string` = `'1.2.840.113549.1.9.16.2.47'`

Signing Certificate V2

#### PKCS9.ETS_SIGNING_LOCATION

> **ETS_SIGNING_LOCATION**: `string` = `'1.2.840.113549.1.9.16.2.17'`

Signing Location

#### PKCS9.EXTENSION_REQUEST

> **EXTENSION_REQUEST**: `string` = `'1.2.840.113549.1.9.14'`

Extension Request

#### PKCS9.MESSAGE_DIGEST

> **MESSAGE_DIGEST**: `string` = `'1.2.840.113549.1.9.4'`

Message Digest

#### PKCS9.SIGNING_TIME

> **SIGNING_TIME**: `string` = `'1.2.840.113549.1.9.5'`

Signing Time

#### PKCS9.TIME_STAMP_TOKEN

> **TIME_STAMP_TOKEN**: `string` = `'1.2.840.113549.1.9.16.2.14'`

Time Stamp Token

### PKIX

> **PKIX**: `object`

PKIX (Public Key Infrastructure X.509)

#### PKIX.ID_PKIX_OCSP_BASIC

> **ID_PKIX_OCSP_BASIC**: `string` = `'1.3.6.1.5.5.7.48.1.1'`

OCSP Basic Response

#### PKIX.ID_PKIX_OCSP_NONCE

> **ID_PKIX_OCSP_NONCE**: `string` = `'1.3.6.1.5.5.7.48.1.2'`

OCSP Nonce Extension

### RSA

> **RSA**: `object`

RSA Algorithms

#### RSA.ENCRYPTION

> **ENCRYPTION**: `string` = `'1.2.840.113549.1.1.1'`

RSA Encryption

#### RSA.MD2_WITH_RSA

> **MD2_WITH_RSA**: `string` = `'1.2.840.113549.1.1.2'`

MD2 with RSA Signature

#### RSA.MD5_WITH_RSA

> **MD5_WITH_RSA**: `string` = `'1.2.840.113549.1.1.4'`

MD5 with RSA Signature

#### RSA.MGF1

> **MGF1**: `string` = `'1.2.840.113549.1.1.8'`

Mask Generation Function 1

#### RSA.PSPECIFIED

> **PSPECIFIED**: `string` = `'1.2.840.113549.1.1.9'`

P Source specified directly (id-pSpecified)

#### RSA.RSAES_OAEP

> **RSAES_OAEP**: `string` = `'1.2.840.113549.1.1.7'`

RSAES-OAEP Key Transport

#### RSA.RSASSA_PSS

> **RSASSA_PSS**: `string` = `'1.2.840.113549.1.1.10'`

RSASSA-PSS Signature

#### RSA.SHA1_WITH_RSA

> **SHA1_WITH_RSA**: `string` = `'1.2.840.113549.1.1.5'`

SHA-1 with RSA Signature

#### RSA.SHA256_WITH_RSA

> **SHA256_WITH_RSA**: `string` = `'1.2.840.113549.1.1.11'`

SHA-256 with RSA Signature

#### RSA.SHA384_WITH_RSA

> **SHA384_WITH_RSA**: `string` = `'1.2.840.113549.1.1.12'`

SHA-384 with RSA Signature

#### RSA.SHA512_WITH_RSA

> **SHA512_WITH_RSA**: `string` = `'1.2.840.113549.1.1.13'`

SHA-512 with RSA Signature
