import { Asn1ParseError } from '../errors/Asn1ParseError.js'
import { Asn1Node, TagClass, UniversalTag } from './Asn1Node.js'

/** Reads a BOOLEAN. Any non-zero octet is TRUE (BER). */
export function readBoolean(node: Asn1Node): boolean {
    const content = node.expect(UniversalTag.Boolean).bytes()
    if (content.length !== 1) {
        throw new Asn1ParseError('BOOLEAN must be exactly one octet')
    }
    return content[0] !== 0
}

export function readNull(node: Asn1Node): null {
    if (node.expect(UniversalTag.Null).bytes().length !== 0) {
        throw new Asn1ParseError('NULL must be empty')
    }
    return null
}

/** Reads an INTEGER's two's-complement content octets. */
export function readIntegerBytes(node: Asn1Node): Uint8Array<ArrayBuffer> {
    const content = node.expect(UniversalTag.Integer).bytes()
    if (content.length === 0) {
        throw new Asn1ParseError('INTEGER must not be empty')
    }
    return content
}

/** Reads an INTEGER as a bigint. */
export function readBigInt(node: Asn1Node): bigint {
    return twosComplementToBigInt(readIntegerBytes(node))
}

/** Reads an INTEGER as a number, throwing if it is not a safe integer. */
export function readNumber(node: Asn1Node): number {
    return toSafeNumber(readBigInt(node))
}

export function readEnumerated(node: Asn1Node): number {
    const content = node.expect(UniversalTag.Enumerated).bytes()
    if (content.length === 0) {
        throw new Asn1ParseError('ENUMERATED must not be empty')
    }
    return toSafeNumber(twosComplementToBigInt(content))
}

/** Reads an OBJECT IDENTIFIER in dotted form. */
export function readOid(node: Asn1Node): string {
    const content = node.expect(UniversalTag.ObjectIdentifier).bytes()
    if (content.length === 0 || content[content.length - 1] & 0x80) {
        throw new Asn1ParseError('Truncated OBJECT IDENTIFIER')
    }
    const arcs: bigint[] = []
    let arc = 0n
    for (let i = 0; i < content.length; i++) {
        if (arc === 0n && content[i] === 0x80) {
            throw new Asn1ParseError('Non-minimal OBJECT IDENTIFIER arc')
        }
        arc = (arc << 7n) | BigInt(content[i] & 0x7f)
        if (!(content[i] & 0x80)) {
            arcs.push(arc)
            arc = 0n
        }
    }
    const first = arcs[0] < 80n ? arcs[0] / 40n : 2n
    return [first, arcs[0] - first * 40n, ...arcs.slice(1)].join('.')
}

export function readOctetString(node: Asn1Node): Uint8Array<ArrayBuffer> {
    return node.expect(UniversalTag.OctetString).bytes()
}

/** Reads a BIT STRING as its whole octets and the unused bit count. */
export function readBitString(node: Asn1Node): {
    bytes: Uint8Array<ArrayBuffer>
    unusedBits: number
} {
    node.expect(UniversalTag.BitString)
    // A constructed (BER) BIT STRING: every segment carries its own leading octet
    const segments = node.constructed ? node.children : [node]
    const parts: Uint8Array[] = []
    let unusedBits = 0
    segments.forEach((segment, i) => {
        const content = segment.expect(UniversalTag.BitString).bytes()
        if (content.length === 0 || content[0] > 7) {
            throw new Asn1ParseError('Invalid BIT STRING')
        }
        if (
            content[0] !== 0 &&
            (i < segments.length - 1 || content.length === 1)
        ) {
            throw new Asn1ParseError('Invalid BIT STRING unused bits')
        }
        unusedBits = content[0]
        parts.push(content.subarray(1))
    })
    const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
    let offset = 0
    for (const part of parts) {
        bytes.set(part, offset)
        offset += part.length
    }
    return { bytes, unusedBits }
}

/** Reads a named bit list BIT STRING as booleans (bit 0 first). */
export function readNamedBits(node: Asn1Node): boolean[] {
    const { bytes, unusedBits } = readBitString(node)
    const bits: boolean[] = []
    for (let i = 0; i < bytes.length * 8 - unusedBits; i++) {
        bits.push((bytes[i >> 3] & (0x80 >> (i & 7))) !== 0)
    }
    return bits
}

/** Reads any of the character string types as a JS string. */
export function readString(node: Asn1Node): string {
    const content = node.bytes()
    switch (node.tagClass === TagClass.Universal ? node.tag : -1) {
        case UniversalTag.UTF8String:
            return new TextDecoder('utf-8', { fatal: true }).decode(content)
        case UniversalTag.PrintableString:
        case UniversalTag.IA5String:
        case UniversalTag.VisibleString:
        case UniversalTag.TeletexString:
            return String.fromCharCode(...content)
        case UniversalTag.BMPString: {
            if (content.length % 2) {
                throw new Asn1ParseError('BMPString has an odd length')
            }
            let out = ''
            for (let i = 0; i < content.length; i += 2) {
                out += String.fromCharCode((content[i] << 8) | content[i + 1])
            }
            return out
        }
        case UniversalTag.UniversalString: {
            if (content.length % 4) {
                throw new Asn1ParseError(
                    'UniversalString length is not a multiple of 4',
                )
            }
            const view = new DataView(
                content.buffer,
                content.byteOffset,
                content.length,
            )
            let out = ''
            for (let i = 0; i < content.length; i += 4) {
                out += String.fromCodePoint(view.getUint32(i))
            }
            return out
        }
        default:
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected a character string, got ${node.describe()}`,
            )
    }
}

/** Reads a UTCTime or GeneralizedTime as a Date. */
export function readTime(node: Asn1Node): Date {
    const text = String.fromCharCode(...node.bytes())
    if (node.is(UniversalTag.UTCTime)) {
        const m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?(Z|[+-]\d{4})$/.exec(
            text,
        )
        if (!m) throw new Asn1ParseError(`Invalid UTCTime: ${text}`)
        const yy = Number(m[1])
        return makeDate(
            yy < 50 ? 2000 + yy : 1900 + yy,
            m.slice(2, 7),
            '',
            m[7],
            text,
        )
    }
    if (node.is(UniversalTag.GeneralizedTime)) {
        const m =
            /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)?(\d\d)?(?:[.,](\d+))?(Z|[+-]\d{4})?$/.exec(
                text,
            )
        if (!m) throw new Asn1ParseError(`Invalid GeneralizedTime: ${text}`)
        return makeDate(
            Number(m[1]),
            m.slice(2, 7),
            m[7] ?? '',
            m[8] ?? 'Z',
            text,
        )
    }
    throw new Asn1ParseError(
        `Invalid ASN.1 structure: expected UTCTime or GeneralizedTime, got ${node.describe()}`,
    )
}

function makeDate(
    year: number,
    [month, day, hour, minute = '0', second = '0']: (string | undefined)[],
    fraction: string,
    zone: string,
    text: string,
): Date {
    const ms = Math.round(Number(`0.${fraction || '0'}`) * 1000)
    let time = Date.UTC(
        year,
        Number(month) - 1,
        Number(day),
        Number(hour),
        Number(minute),
        Number(second),
        ms,
    )
    const date = new Date(time)
    if (
        Number.isNaN(time) ||
        date.getUTCMonth() !== Number(month) - 1 ||
        date.getUTCDate() !== Number(day) ||
        Number(hour) > 23 ||
        Number(minute) > 59 ||
        Number(second) > 59
    ) {
        throw new Asn1ParseError(`Invalid time: ${text}`)
    }
    if (zone !== 'Z') {
        const sign = zone[0] === '-' ? -1 : 1
        time -=
            sign *
            (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3))) *
            60000
    }
    return new Date(time)
}

function twosComplementToBigInt(bytes: Uint8Array): bigint {
    let value = 0n
    for (const b of bytes) value = (value << 8n) | BigInt(b)
    if (bytes[0] & 0x80) {
        value -= 1n << BigInt(bytes.length * 8)
    }
    return value
}

function toSafeNumber(value: bigint): number {
    if (
        value > BigInt(Number.MAX_SAFE_INTEGER) ||
        value < BigInt(Number.MIN_SAFE_INTEGER)
    ) {
        throw new Asn1ParseError(`INTEGER ${value} is too large for a number`)
    }
    return Number(value)
}
