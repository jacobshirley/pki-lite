/**
 * ASN.1 DER Constants
 */

/**
 * ASN.1 Tag Classes (0-3 values, as used in asn1js API)
 */
export const TagClass = {
    UNIVERSAL: 1, // 0b00 (note: asn1js uses 1 for UNIVERSAL)
    APPLICATION: 2, // 0b01
    CONTEXT_SPECIFIC: 3, // 0b10
    PRIVATE: 4, // 0b11
} as const

/**
 * ASN.1 Tag Class encoded values (for actual byte encoding)
 */
export const TagClassEncoded = {
    UNIVERSAL: 0x00,
    APPLICATION: 0x40,
    CONTEXT_SPECIFIC: 0x80,
    PRIVATE: 0xc0,
} as const

/**
 * ASN.1 Tag Numbers (Universal class)
 */
export const TagNumber = {
    END_OF_CONTENT: 0,
    BOOLEAN: 1,
    INTEGER: 2,
    BIT_STRING: 3,
    OCTET_STRING: 4,
    NULL: 5,
    OBJECT_IDENTIFIER: 6,
    OBJECT_DESCRIPTOR: 7,
    EXTERNAL: 8,
    REAL: 9,
    ENUMERATED: 10,
    EMBEDDED_PDV: 11,
    UTF8_STRING: 12,
    RELATIVE_OID: 13,
    TIME: 14,
    SEQUENCE: 16,
    SET: 17,
    NUMERIC_STRING: 18,
    PRINTABLE_STRING: 19,
    TELETEX_STRING: 20,
    VIDEOTEX_STRING: 21,
    IA5_STRING: 22,
    UTC_TIME: 23,
    GENERALIZED_TIME: 24,
    GRAPHIC_STRING: 25,
    VISIBLE_STRING: 26,
    GENERAL_STRING: 27,
    UNIVERSAL_STRING: 28,
    CHARACTER_STRING: 29,
    BMP_STRING: 30,
    DATE: 31,
    TIME_OF_DAY: 32,
    DATE_TIME: 33,
    DURATION: 34,
} as const

/**
 * Constructed bit for tag encoding
 */
export const CONSTRUCTED_BIT = 0x20

/**
 * Long form tag marker
 */
export const LONG_FORM_TAG = 0x1f

/**
 * Length encoding constants
 */
export const LENGTH_LONG_FORM_BIT = 0x80
export const LENGTH_INDEFINITE = 0x80
