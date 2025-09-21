/**
 * CMSVersion values as defined in RFC 5652.
 *
 * @asn
 * ```asn
 * CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
 * ```
 */
export type CMSVersion = number

export const CMSVersion = {
    v0: 0,
    v1: 1,
    v2: 2,
    v3: 3,
    v4: 4,
    v5: 5,
} as const
