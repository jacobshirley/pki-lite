/**
 * @file OIDs.ts
 *
 * This file defines a centralized collection of common Object Identifiers (OIDs)
 * used throughout the PKI-Lite library. These OIDs represent various algorithms,
 * data formats, and standards used in cryptography and PKI.
 */

/**
 * Object Identifiers (OIDs) for cryptographic algorithms, data formats, and PKI standards.
 */
export const OIDs = {
    /**
     * RSA Algorithms
     */
    RSA: {
        /** RSA Encryption */
        ENCRYPTION: '1.2.840.113549.1.1.1',
        /** MD2 with RSA Signature */
        MD2_WITH_RSA: '1.2.840.113549.1.1.2',
        /** MD5 with RSA Signature */
        MD5_WITH_RSA: '1.2.840.113549.1.1.4',
        /** SHA-1 with RSA Signature */
        SHA1_WITH_RSA: '1.2.840.113549.1.1.5',
        /** SHA-256 with RSA Signature */
        SHA256_WITH_RSA: '1.2.840.113549.1.1.11',
        /** SHA-384 with RSA Signature */
        SHA384_WITH_RSA: '1.2.840.113549.1.1.12',
        /** SHA-512 with RSA Signature */
        SHA512_WITH_RSA: '1.2.840.113549.1.1.13',
        /** RSASSA-PSS Signature */
        RSASSA_PSS: '1.2.840.113549.1.1.10',
        /** RSAES-OAEP Key Transport */
        RSAES_OAEP: '1.2.840.113549.1.1.7',
        /** Mask Generation Function 1 */
        MGF1: '1.2.840.113549.1.1.8',
        /** P Source specified directly (id-pSpecified) */
        PSPECIFIED: '1.2.840.113549.1.1.9',
    },

    /**
     * Elliptic Curve Cryptography
     */
    EC: {
        /** Elliptic Curve Diffie-Hellman (ECDH) */
        ECDH: '1.2.840.10045.3.1.1',
        /** Elliptic Curve Public Key */
        PUBLIC_KEY: '1.2.840.10045.2.1',
        /** SHA-1 with ECDSA Signature */
        SHA1_WITH_ECDSA: '1.2.840.10045.4.1',
        /** SHA-256 with ECDSA Signature */
        SHA256_WITH_ECDSA: '1.2.840.10045.4.3.2',
        /** SHA-384 with ECDSA Signature */
        SHA384_WITH_ECDSA: '1.2.840.10045.4.3.3',
        /** SHA-512 with ECDSA Signature */
        SHA512_WITH_ECDSA: '1.2.840.10045.4.3.4',
    },

    /**
     * Named Elliptic Curves
     */
    CURVES: {
        /** NIST P-256 / secp256r1 */
        SECP256R1: '1.2.840.10045.3.1.7',
        /** NIST P-384 / secp384r1 */
        SECP384R1: '1.3.132.0.34',
        /** NIST P-521 / secp521r1 */
        SECP521R1: '1.3.132.0.35',
        /** secp256k1 (used in Bitcoin and other cryptocurrencies) */
        SECP256K1: '1.3.132.0.10',
        /** Ed25519 curve for EdDSA */
        ED25519: '1.3.101.112',
        /** Ed448 curve for EdDSA */
        ED448: '1.3.101.113',
        /** X25519 curve for ECDH */
        X25519: '1.3.101.110',
        /** X448 curve for ECDH */
        X448: '1.3.101.111',
    },

    /**
     * DSA Algorithms
     */
    DSA: {
        /** Digital Signature Algorithm */
        ALGORITHM: '1.2.840.10040.4.1',
        /** SHA-1 with DSA Signature */
        SHA1_WITH_DSA: '1.2.840.10040.4.3',
        /** SHA-256 with DSA Signature */
        SHA256_WITH_DSA: '2.16.840.1.101.3.4.3.2',
    },

    /**
     * Hash Functions
     */
    HASH: {
        /** MD5 Hash */
        MD5: '1.2.840.113549.2.5',
        /** SHA-1 Hash */
        SHA1: '1.3.14.3.2.26',
        /** SHA-256 Hash */
        SHA256: '2.16.840.1.101.3.4.2.1',
        /** SHA-384 Hash */
        SHA384: '2.16.840.1.101.3.4.2.2',
        /** SHA-512 Hash */
        SHA512: '2.16.840.1.101.3.4.2.3',
        /** HMAC with SHA-1 */
        HMAC_SHA1: '1.2.840.113549.2.7',
        /** HMAC with SHA-256 */
        HMAC_SHA256: '1.2.840.113549.2.9',
        /** HMAC with SHA-384 */
        HMAC_SHA384: '1.2.840.113549.2.10',
        /** HMAC with SHA-512 */
        HMAC_SHA512: '1.2.840.113549.2.11',
    },

    /**
     * Symmetric Encryption Algorithms
     */
    ENCRYPTION: {
        /** Triple DES in CBC mode */
        DES_EDE3_CBC: '1.2.840.113549.3.7',
        /** AES-128 in CBC mode */
        AES_128_CBC: '2.16.840.1.101.3.4.1.2',
        /** AES-192 in CBC mode */
        AES_192_CBC: '2.16.840.1.101.3.4.1.22',
        /** AES-256 in CBC mode */
        AES_256_CBC: '2.16.840.1.101.3.4.1.42',
        /** AES-128 in GCM mode */
        AES_128_GCM: '2.16.840.1.101.3.4.1.6',
        /** AES-192 in GCM mode */
        AES_192_GCM: '2.16.840.1.101.3.4.1.26',
        /** AES-256 in GCM mode */
        AES_256_GCM: '2.16.840.1.101.3.4.1.46',
        /** AES-128 in CCM mode */
        AES_128_CCM: '2.16.840.1.101.3.4.1.7',
        /** AES-192 in CCM mode */
        AES_192_CCM: '2.16.840.1.101.3.4.1.27',
        /** AES-256 in CCM mode */
        AES_256_CCM: '2.16.840.1.101.3.4.1.47',
        /** AES-128 in ECB mode */
        AES_128_ECB: '2.16.840.1.101.3.4.1.1',
        /** AES-192 in ECB mode */
        AES_192_ECB: '2.16.840.1.101.3.4.1.21',
        /** AES-256 in ECB mode */
        AES_256_ECB: '2.16.840.1.101.3.4.1.41',
    },

    /**
     * PKCS#7/CMS Content Types
     */
    PKCS7: {
        /** Data content type */
        DATA: '1.2.840.113549.1.7.1',
        /** SignedData content type */
        SIGNED_DATA: '1.2.840.113549.1.7.2',
        /** EnvelopedData content type */
        ENVELOPED_DATA: '1.2.840.113549.1.7.3',
        /** SignedAndEnvelopedData content type */
        SIGNED_AND_ENVELOPED_DATA: '1.2.840.113549.1.7.4',
        /** DigestedData content type */
        DIGESTED_DATA: '1.2.840.113549.1.7.5',
        /** EncryptedData content type */
        ENCRYPTED_DATA: '1.2.840.113549.1.7.6',
        /** AuthenticatedData content type */
        AUTHENTICATED_DATA: '1.2.840.113549.1.7.7',
        /** AuthEnvelopedData content type */
        AUTH_ENVELOPED_DATA: '1.2.840.113549.1.9.16.1.23',
    },

    /**
     * X.509 Certificate Extensions
     */
    EXTENSION: {
        /** Subject Key Identifier */
        SUBJECT_KEY_IDENTIFIER: '2.5.29.14',
        /** Key Usage */
        KEY_USAGE: '2.5.29.15',
        /** Subject Alternative Name */
        SUBJECT_ALT_NAME: '2.5.29.17',
        /** Basic Constraints */
        BASIC_CONSTRAINTS: '2.5.29.19',
        /** CRL Number */
        CRL_NUMBER: '2.5.29.20',
        /** CRL Distribution Points */
        CRL_DISTRIBUTION_POINTS: '2.5.29.31',
        /** Certificate Policies */
        CERTIFICATE_POLICIES: '2.5.29.32',
        /** Authority Key Identifier */
        AUTHORITY_KEY_IDENTIFIER: '2.5.29.35',
        /** Extended Key Usage */
        EXTENDED_KEY_USAGE: '2.5.29.37',
        /** Authority Information Access */
        AUTHORITY_INFO_ACCESS: '1.3.6.1.5.5.7.1.1',
        /** CRL Reason Code */
        CRL_REASON_CODE: '2.5.29.21',
    },

    /**
     * AUTHORITY_INFO_ACCESS extension access methods
     */
    AUTHORITY_INFO_ACCESS: {
        /** CA Issuers */
        CA_ISSUERS: '1.3.6.1.5.5.7.48.2',
        /** OCSP */
        OCSP: '1.3.6.1.5.5.7.48.1',
    },

    /**
     * Extended Key Usage Purpose OIDs
     */
    EKU: {
        /** TLS Web Server Authentication */
        SERVER_AUTH: '1.3.6.1.5.5.7.3.1',
        /** TLS Web Client Authentication */
        CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
        /** Code Signing */
        CODE_SIGNING: '1.3.6.1.5.5.7.3.3',
        /** Email Protection */
        EMAIL_PROTECTION: '1.3.6.1.5.5.7.3.4',
        /** Time Stamping */
        TIME_STAMPING: '1.3.6.1.5.5.7.3.8',
        /** OCSP Signing */
        OCSP_SIGNING: '1.3.6.1.5.5.7.3.9',
        /** Document Signing (Microsoft) */
        DOCUMENT_SIGNING: '1.3.6.1.4.1.311.10.3.12',
    },

    /**
     * PKIX (Public Key Infrastructure X.509)
     */
    PKIX: {
        /** OCSP Basic Response */
        ID_PKIX_OCSP_BASIC: '1.3.6.1.5.5.7.48.1.1',
        /** OCSP Nonce Extension */
        ID_PKIX_OCSP_NONCE: '1.3.6.1.5.5.7.48.1.2',
    },

    /**
     * Distinguished Name (DN) components
     */
    DN: {
        /** Common Name */
        CN: '2.5.4.3',
        /** Country */
        C: '2.5.4.6',
        /** State or Province */
        ST: '2.5.4.8',
        /** Locality */
        L: '2.5.4.7',
        /** Organization */
        O: '2.5.4.10',
        /** Organizational Unit */
        OU: '2.5.4.11',
        /** Email Address (PKCS#9) */
        EMAIL: '1.2.840.113549.1.9.1',
    },

    /**
     * PKCS#9 Attributes
     */
    PKCS9: {
        /** Email Address */
        EMAIL_ADDRESS: '1.2.840.113549.1.9.1',
        /** Content Type */
        CONTENT_TYPE: '1.2.840.113549.1.9.3',
        /** Message Digest */
        MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
        /** Signing Time */
        SIGNING_TIME: '1.2.840.113549.1.9.5',
        /** Challenge Password */
        CHALLENGE_PASSWORD: '1.2.840.113549.1.9.7',
        /** Extension Request */
        EXTENSION_REQUEST: '1.2.840.113549.1.9.14',
        /** Time Stamp Token */
        TIME_STAMP_TOKEN: '1.2.840.113549.1.9.16.2.14',
        /** Signing Certificate */
        ETS_SIGNING_CERTIFICATE: '1.2.840.113549.1.9.16.2.12',
        /** Signing Certificate V2 */
        ETS_SIGNING_CERTIFICATE_V2: '1.2.840.113549.1.9.16.2.47',
        /** Signing Location */
        ETS_SIGNING_LOCATION: '1.2.840.113549.1.9.16.2.17',
        /** Commitment Type Indication */
        ETS_COMMITMENT_TYPE_INDICATION: '1.2.840.113549.1.9.16.2.16',
        /** Signature Policy Identifier */
        ETS_SIGNATURE_POLICY_IDENTIFIER: '1.2.840.113549.1.9.16.2.15',
        /** Revocation Values */
        ETS_REVOCATION_VALUES: '1.2.840.113549.1.9.16.2.24',
    },
    /**
     * PKCS#5 OIDs
     */
    PKCS5: {
        /** Password-Based Encryption Scheme 2 */
        PBES2: '1.2.840.113549.1.5.13',
        /** PBKDF2 Key Derivation Function */
        PBKDF2: '1.2.840.113549.1.5.12',
    },
    /**
     * PKCS#12 OIDs
     */
    PKCS12: {
        /** Bag types under pkcs-12PbeIds */
        BAGS: {
            /** keyBag */
            KEY_BAG: '1.2.840.113549.1.12.10.1.1',
            /** pkcs8ShroudedKeyBag */
            PKCS8_SHROUDED_KEY_BAG: '1.2.840.113549.1.12.10.1.2',
            /** certBag */
            CERT_BAG: '1.2.840.113549.1.12.10.1.3',
            /** crlBag */
            CRL_BAG: '1.2.840.113549.1.12.10.1.4',
            /** secretBag */
            SECRET_BAG: '1.2.840.113549.1.12.10.1.5',
            /** safeContentsBag */
            SAFE_CONTENTS_BAG: '1.2.840.113549.1.12.10.1.6',
        },
        /** Certificate types inside CertBag */
        CERT_TYPES: {
            /** x509Certificate */
            X509_CERT: '1.2.840.113549.1.9.22.1',
            /** sdsiCertificate */
            SDSI_CERT: '1.2.840.113549.1.9.22.2',
        },
        /** Password-based encryption schemes (pkcs-12PbeIds) */
        PBE: {
            /** pbeWithSHAAnd128BitRC4 */
            SHA1_RC4_128: '1.2.840.113549.1.12.1.1',
            /** pbeWithSHAAnd40BitRC4 */
            SHA1_RC4_40: '1.2.840.113549.1.12.1.2',
            /** pbeWithSHAAnd3-KeyTripleDES-CBC */
            SHA1_3DES_3KEY_CBC: '1.2.840.113549.1.12.1.3',
            /** pbeWithSHAAnd2-KeyTripleDES-CBC */
            SHA1_3DES_2KEY_CBC: '1.2.840.113549.1.12.1.4',
            /** pbeWithSHAAnd128BitRC2-CBC */
            SHA1_RC2_128_CBC: '1.2.840.113549.1.12.1.5',
            /** pbeWithSHAAnd40BitRC2-CBC */
            SHA1_RC2_40_CBC: '1.2.840.113549.1.12.1.6',
        },
    },
    /**
     * OTHER_REV_INFO
     */
    OTHER_REV_INFO: {
        /** OCSP */
        OCSP: '1.3.6.1.5.5.7.16.2',
    },
    /**
     * Adobe OIDs
     */
    ADOBE: {
        /** Revocation Info Archival */
        REVOCATION_INFO_ARCHIVAL: '1.2.840.113583.1.1.8',
    },
    getOidFriendlyName,
}

/**
 * Mapping of OIDs to their friendly names.
 * This can be used for display purposes or debugging.
 */
export const OIDToFriendlyName: Record<string, string> = {
    // RSA
    [OIDs.RSA.ENCRYPTION]: 'RSA',
    [OIDs.RSA.MD2_WITH_RSA]: 'MD2withRSA',
    [OIDs.RSA.MD5_WITH_RSA]: 'MD5withRSA',
    [OIDs.RSA.SHA1_WITH_RSA]: 'SHA1withRSA',
    [OIDs.RSA.SHA256_WITH_RSA]: 'SHA256withRSA',
    [OIDs.RSA.SHA384_WITH_RSA]: 'SHA384withRSA',
    [OIDs.RSA.SHA512_WITH_RSA]: 'SHA512withRSA',
    [OIDs.RSA.RSASSA_PSS]: 'RSASSA-PSS',
    [OIDs.RSA.RSAES_OAEP]: 'RSAES-OAEP',

    // EC
    [OIDs.EC.PUBLIC_KEY]: 'ECDSA',
    [OIDs.EC.SHA1_WITH_ECDSA]: 'SHA1withECDSA',
    [OIDs.EC.SHA256_WITH_ECDSA]: 'SHA256withECDSA',
    [OIDs.EC.SHA384_WITH_ECDSA]: 'SHA384withECDSA',
    [OIDs.EC.SHA512_WITH_ECDSA]: 'SHA512withECDSA',
    [OIDs.EC.ECDH]: 'ECDH',

    // Named Curves
    [OIDs.CURVES.SECP256R1]: 'secp256r1 (NIST P-256)',
    [OIDs.CURVES.SECP384R1]: 'secp384r1 (NIST P-384)',
    [OIDs.CURVES.SECP521R1]: 'secp521r1 (NIST P-521)',
    [OIDs.CURVES.SECP256K1]: 'secp256k1',
    [OIDs.CURVES.ED25519]: 'Ed25519',
    [OIDs.CURVES.ED448]: 'Ed448',
    [OIDs.CURVES.X25519]: 'X25519',
    [OIDs.CURVES.X448]: 'X448',

    // DSA
    [OIDs.DSA.ALGORITHM]: 'DSA',
    [OIDs.DSA.SHA1_WITH_DSA]: 'SHA1withDSA',
    [OIDs.DSA.SHA256_WITH_DSA]: 'SHA256withDSA',

    // Hash Functions
    [OIDs.HASH.MD5]: 'MD5',
    [OIDs.HASH.SHA1]: 'SHA1',
    [OIDs.HASH.SHA256]: 'SHA256',
    [OIDs.HASH.SHA384]: 'SHA384',
    [OIDs.HASH.SHA512]: 'SHA512',
    [OIDs.HASH.HMAC_SHA256]: 'HMAC-SHA256',

    // Symmetric Encryption
    [OIDs.ENCRYPTION.DES_EDE3_CBC]: 'DES-EDE3-CBC',
    [OIDs.ENCRYPTION.AES_128_CBC]: 'AES-128-CBC',
    [OIDs.ENCRYPTION.AES_192_CBC]: 'AES-192-CBC',
    [OIDs.ENCRYPTION.AES_256_CBC]: 'AES-256-CBC',
    [OIDs.ENCRYPTION.AES_128_GCM]: 'AES-128-GCM',
    [OIDs.ENCRYPTION.AES_192_GCM]: 'AES-192-GCM',
    [OIDs.ENCRYPTION.AES_256_GCM]: 'AES-256-GCM',
    [OIDs.ENCRYPTION.AES_128_CCM]: 'AES-128-CCM',
    [OIDs.ENCRYPTION.AES_192_CCM]: 'AES-192-CCM',
    [OIDs.ENCRYPTION.AES_256_CCM]: 'AES-256-CCM',
    [OIDs.ENCRYPTION.AES_128_ECB]: 'AES-128-ECB',
    [OIDs.ENCRYPTION.AES_192_ECB]: 'AES-192-ECB',
    [OIDs.ENCRYPTION.AES_256_ECB]: 'AES-256-ECB',

    // PKCS#7/CMS
    [OIDs.PKCS7.DATA]: 'PKCS#7 Data',
    [OIDs.PKCS7.SIGNED_DATA]: 'PKCS#7 SignedData',
    [OIDs.PKCS7.ENVELOPED_DATA]: 'PKCS#7 EnvelopedData',
    [OIDs.PKCS7.SIGNED_AND_ENVELOPED_DATA]: 'PKCS#7 SignedAndEnvelopedData',
    [OIDs.PKCS7.DIGESTED_DATA]: 'PKCS#7 DigestedData',
    [OIDs.PKCS7.ENCRYPTED_DATA]: 'PKCS#7 EncryptedData',
    [OIDs.PKCS7.AUTHENTICATED_DATA]: 'PKCS#7 AuthenticatedData',
    [OIDs.PKCS7.AUTH_ENVELOPED_DATA]: 'PKCS#7 AuthEnvelopedData',

    // X.509 Extensions
    [OIDs.EXTENSION.SUBJECT_KEY_IDENTIFIER]: 'Subject Key Identifier',
    [OIDs.EXTENSION.KEY_USAGE]: 'Key Usage',
    [OIDs.EXTENSION.SUBJECT_ALT_NAME]: 'Subject Alternative Name',
    [OIDs.EXTENSION.BASIC_CONSTRAINTS]: 'Basic Constraints',
    [OIDs.EXTENSION.CRL_NUMBER]: 'CRL Number',
    [OIDs.EXTENSION.CRL_DISTRIBUTION_POINTS]: 'CRL Distribution Points',
    [OIDs.EXTENSION.CERTIFICATE_POLICIES]: 'Certificate Policies',
    [OIDs.EXTENSION.AUTHORITY_KEY_IDENTIFIER]: 'Authority Key Identifier',
    [OIDs.EXTENSION.EXTENDED_KEY_USAGE]: 'Extended Key Usage',
    [OIDs.EXTENSION.AUTHORITY_INFO_ACCESS]: 'Authority Information Access',

    // Extended Key Usage
    [OIDs.EKU.SERVER_AUTH]: 'TLS Web Server Authentication',
    [OIDs.EKU.CLIENT_AUTH]: 'TLS Web Client Authentication',
    [OIDs.EKU.CODE_SIGNING]: 'Code Signing',
    [OIDs.EKU.EMAIL_PROTECTION]: 'Email Protection',
    [OIDs.EKU.TIME_STAMPING]: 'Time Stamping',
    [OIDs.EKU.OCSP_SIGNING]: 'OCSP Signing',
    [OIDs.EKU.DOCUMENT_SIGNING]: 'Document Signing',

    // Distinguished Name
    [OIDs.DN.CN]: 'Common Name (CN)',
    [OIDs.DN.C]: 'Country (C)',
    [OIDs.DN.ST]: 'State or Province (ST)',
    [OIDs.DN.L]: 'Locality (L)',
    [OIDs.DN.O]: 'Organization (O)',
    [OIDs.DN.OU]: 'Organizational Unit (OU)',
    [OIDs.DN.EMAIL]: 'Email Address',

    // PKCS#9 Attributes
    [OIDs.PKCS9.EMAIL_ADDRESS]: 'Email Address',
    [OIDs.PKCS9.CONTENT_TYPE]: 'Content Type',
    [OIDs.PKCS9.MESSAGE_DIGEST]: 'Message Digest',
    [OIDs.PKCS9.SIGNING_TIME]: 'Signing Time',
    [OIDs.PKCS9.CHALLENGE_PASSWORD]: 'Challenge Password',
    [OIDs.PKCS9.EXTENSION_REQUEST]: 'Extension Request',
    [OIDs.PKCS9.TIME_STAMP_TOKEN]: 'Time Stamp Token',
    [OIDs.PKCS9.ETS_SIGNING_CERTIFICATE]: 'Signing Certificate',
    [OIDs.PKCS9.ETS_SIGNING_CERTIFICATE_V2]: 'Signing Certificate V2',
    [OIDs.PKCS9.ETS_SIGNING_LOCATION]: 'Signing Location',
    [OIDs.PKCS9.ETS_COMMITMENT_TYPE_INDICATION]: 'Commitment Type Indication',
    [OIDs.PKCS9.ETS_SIGNATURE_POLICY_IDENTIFIER]: 'Signature Policy Identifier',
    [OIDs.PKCS9.ETS_REVOCATION_VALUES]: 'Revocation Values',

    // PKCS#5
    [OIDs.PKCS5.PBES2]: 'PBES2',

    // OTHER_REV_INFO
    [OIDs.OTHER_REV_INFO.OCSP]: 'OCSP',

    // Adobe
    [OIDs.ADOBE.REVOCATION_INFO_ARCHIVAL]: 'Adobe Revocation Info Archival',

    // PKCS#12 Bags
    [OIDs.PKCS12.BAGS.KEY_BAG]: 'PKCS#12 keyBag',
    [OIDs.PKCS12.BAGS.PKCS8_SHROUDED_KEY_BAG]: 'PKCS#12 pkcs8ShroudedKeyBag',
    [OIDs.PKCS12.BAGS.CERT_BAG]: 'PKCS#12 certBag',
    [OIDs.PKCS12.BAGS.CRL_BAG]: 'PKCS#12 crlBag',
    [OIDs.PKCS12.BAGS.SECRET_BAG]: 'PKCS#12 secretBag',
    [OIDs.PKCS12.BAGS.SAFE_CONTENTS_BAG]: 'PKCS#12 safeContentsBag',

    // PKCS#12 Cert Types
    [OIDs.PKCS12.CERT_TYPES.X509_CERT]: 'PKCS#12 X.509 Certificate',
    [OIDs.PKCS12.CERT_TYPES.SDSI_CERT]: 'PKCS#12 SDSI Certificate',

    // PKCS#12 PBE algorithms (SHA-1 based)
    [OIDs.PKCS12.PBE.SHA1_RC4_128]: 'PKCS#12 pbeWithSHAAnd128BitRC4',
    [OIDs.PKCS12.PBE.SHA1_RC4_40]: 'PKCS#12 pbeWithSHAAnd40BitRC4',
    [OIDs.PKCS12.PBE.SHA1_3DES_3KEY_CBC]:
        'PKCS#12 pbeWithSHAAnd3-KeyTripleDES-CBC',
    [OIDs.PKCS12.PBE.SHA1_3DES_2KEY_CBC]:
        'PKCS#12 pbeWithSHAAnd2-KeyTripleDES-CBC',
    [OIDs.PKCS12.PBE.SHA1_RC2_128_CBC]: 'PKCS#12 pbeWithSHAAnd128BitRC2-CBC',
    [OIDs.PKCS12.PBE.SHA1_RC2_40_CBC]: 'PKCS#12 pbeWithSHAAnd40BitRC2-CBC',
}

export const OIDToShortName: Record<string, string> = {
    [OIDs.DN.CN]: 'CN',
    [OIDs.DN.C]: 'C',
    [OIDs.DN.ST]: 'ST',
    [OIDs.DN.L]: 'L',
    [OIDs.DN.O]: 'O',
    [OIDs.DN.OU]: 'OU',
    [OIDs.DN.EMAIL]: 'Email',
}

export const ShortNameToOID: Record<string, string> = Object.fromEntries(
    Object.entries(OIDToShortName).map(([oid, shortName]) => [shortName, oid]),
)

/**
 * Get a friendly name for an OID
 *
 * @param oid The OID to get a friendly name for
 * @returns The friendly name if available, otherwise the OID itself
 */
export function getOidFriendlyName(oid: string): string {
    return OIDToFriendlyName[oid] || oid
}

export function getOidShortName(oid: string): string {
    return OIDToShortName[oid] || oid
}

export function getShortNameOid(shortName: string): string {
    return ShortNameToOID[shortName] || shortName
}
