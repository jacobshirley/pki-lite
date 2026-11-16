import * as asn1js from 'asn1js'

/**
 * Every GeneralizedTime value in a DER encoding, as text (`YYYYMMDDHHMMSS[.f]Z`), so
 * tests can check what a structure encodes, not just that it parses back.
 */
export function generalizedTimes(der: ArrayBuffer | Uint8Array): string[] {
    const found: string[] = []
    const walk = (block: asn1js.AsnType) => {
        if (block instanceof asn1js.GeneralizedTime) {
            found.push(new TextDecoder().decode(block.valueBlock.valueHexView))
        }
        const value = (block as { valueBlock?: { value?: unknown } }).valueBlock
            ?.value
        if (Array.isArray(value)) value.forEach(walk)
    }
    walk(asn1js.fromBER(der).result)
    return found
}
