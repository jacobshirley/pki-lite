/** The two tag-class bits of an identifier octet (X.690 8.1.2.2). */
export const TagClass = {
    Universal: 0,
    Application: 1,
    Context: 2,
    Private: 3,
} as const

export type TagClass = (typeof TagClass)[keyof typeof TagClass]

/** Universal tag numbers used by the library (X.680 8.4). */
export const UniversalTag = {
    Boolean: 1,
    Integer: 2,
    BitString: 3,
    OctetString: 4,
    Null: 5,
    ObjectIdentifier: 6,
    Enumerated: 10,
    UTF8String: 12,
    Sequence: 16,
    Set: 17,
    PrintableString: 19,
    TeletexString: 20,
    IA5String: 22,
    UTCTime: 23,
    GeneralizedTime: 24,
    VisibleString: 26,
    UniversalString: 28,
    BMPString: 30,
} as const
