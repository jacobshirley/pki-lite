import { Asn1ParseError } from '../errors/Asn1ParseError.js'
import { Asn1Node, TagClass, UniversalTag } from './Asn1Node.js'

const primitive = (tag: number, content: Uint8Array<ArrayBuffer>) =>
    new Asn1Node({ tag, content })

/** SEQUENCE / SEQUENCE OF. `undefined` entries (absent OPTIONAL fields) are skipped. */
export function sequence(
    children: readonly (Asn1Node | undefined)[],
): Asn1Node {
    return new Asn1Node({
        tag: UniversalTag.Sequence,
        children: children.filter((c): c is Asn1Node => c !== undefined),
    })
}

/**
 * SET / SET OF. Elements are encoded in the given order (not DER-sorted), so a
 * parsed SET re-encodes unchanged.
 */
export function set(children: readonly (Asn1Node | undefined)[]): Asn1Node {
    return new Asn1Node({
        tag: UniversalTag.Set,
        children: children.filter((c): c is Asn1Node => c !== undefined),
    })
}

/** A constructed node with an arbitrary tag, e.g. `[0] { ... }`. */
export function constructed(
    tag: number,
    children: readonly Asn1Node[],
    tagClass: TagClass = TagClass.Context,
): Asn1Node {
    return new Asn1Node({ tagClass, tag, children })
}

export function boolean(value: boolean): Asn1Node {
    return primitive(UniversalTag.Boolean, new Uint8Array([value ? 0xff : 0]))
}

export function nullValue(): Asn1Node {
    return primitive(UniversalTag.Null, new Uint8Array(0))
}

/**
 * INTEGER. A `Uint8Array` is taken as two's-complement content; redundant leading
 * octets are removed so the encoding is minimal (DER).
 */
export function integer(value: bigint | number | Uint8Array): Asn1Node {
    return primitive(UniversalTag.Integer, integerContent(value))
}

/** ENUMERATED, encoded like INTEGER. */
export function enumerated(value: number): Asn1Node {
    return primitive(UniversalTag.Enumerated, integerContent(value))
}

/**
 * INTEGER from an unsigned big-endian magnitude (RSA moduli, serial numbers given as
 * bytes): a 0x00 octet is prepended when the high bit is set.
 */
export function unsignedInteger(bytes: Uint8Array): Asn1Node {
    let start = 0
    while (start < bytes.length - 1 && bytes[start] === 0) start++
    const trimmed = bytes.subarray(start)
    if (trimmed.length === 0) {
        return integer(0)
    }
    const content =
        trimmed[0] & 0x80
            ? new Uint8Array([0, ...trimmed])
            : new Uint8Array(trimmed)
    return primitive(UniversalTag.Integer, content)
}

function integerContent(
    value: bigint | number | Uint8Array,
): Uint8Array<ArrayBuffer> {
    if (value instanceof Uint8Array) {
        if (value.length === 0) {
            throw new Asn1ParseError('INTEGER content must not be empty')
        }
        let start = 0
        while (
            start < value.length - 1 &&
            ((value[start] === 0x00 && !(value[start + 1] & 0x80)) ||
                (value[start] === 0xff && value[start + 1] & 0x80))
        ) {
            start++
        }
        return new Uint8Array(value.subarray(start))
    }
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
        throw new Asn1ParseError(`Not a safe integer: ${value}`)
    }
    let n = BigInt(value)
    const bytes: number[] = []
    // Emit octets until the remaining value is just the sign extension of the last one
    for (;;) {
        const octet = Number(n & 0xffn)
        bytes.unshift(octet)
        n >>= 8n
        if ((n === 0n && !(octet & 0x80)) || (n === -1n && octet & 0x80)) {
            break
        }
    }
    return new Uint8Array(bytes)
}

/** OBJECT IDENTIFIER from dotted form, e.g. `'1.2.840.113549.1.1.11'`. */
export function oid(dotted: string): Asn1Node {
    if (!/^[0-2](\.\d+)+$/.test(dotted)) {
        throw new Asn1ParseError(`Invalid object identifier: ${dotted}`)
    }
    const arcs = dotted.split('.').map(BigInt)
    if (arcs[0] < 2n && arcs[1] > 39n) {
        throw new Asn1ParseError(`Invalid object identifier: ${dotted}`)
    }
    const out: number[] = []
    const push = (arc: bigint) => {
        const digits = [Number(arc & 0x7fn)]
        for (arc >>= 7n; arc > 0n; arc >>= 7n) {
            digits.unshift(Number(arc & 0x7fn) | 0x80)
        }
        out.push(...digits)
    }
    push(arcs[0] * 40n + arcs[1])
    arcs.slice(2).forEach(push)
    return primitive(UniversalTag.ObjectIdentifier, new Uint8Array(out))
}

export function octetString(bytes: Uint8Array): Asn1Node {
    return primitive(UniversalTag.OctetString, new Uint8Array(bytes))
}

/** BIT STRING from whole octets plus the number of unused bits in the last one. */
export function bitString(bytes: Uint8Array, unusedBits = 0): Asn1Node {
    if (
        unusedBits < 0 ||
        unusedBits > 7 ||
        (bytes.length === 0 && unusedBits)
    ) {
        throw new Asn1ParseError(
            `Invalid BIT STRING unused bits: ${unusedBits}`,
        )
    }
    return primitive(
        UniversalTag.BitString,
        new Uint8Array([unusedBits, ...bytes]),
    )
}

/**
 * BIT STRING for a named bit list (`KeyUsage`, `ReasonFlags`, ...): bit 0 is the most
 * significant bit of the first octet; trailing zero bits are dropped (DER).
 */
export function namedBits(bits: readonly boolean[]): Asn1Node {
    const last = bits.lastIndexOf(true)
    if (last === -1) {
        return bitString(new Uint8Array(0))
    }
    const bytes = new Uint8Array(Math.floor(last / 8) + 1)
    for (let i = 0; i <= last; i++) {
        if (bits[i]) bytes[i >> 3] |= 0x80 >> (i & 7)
    }
    return bitString(bytes, 7 - (last & 7))
}

export function utf8String(value: string): Asn1Node {
    return primitive(UniversalTag.UTF8String, new TextEncoder().encode(value))
}

export function printableString(value: string): Asn1Node {
    if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
        throw new Asn1ParseError(`Invalid PrintableString: ${value}`)
    }
    return primitive(UniversalTag.PrintableString, latin1(value))
}

export function ia5String(value: string): Asn1Node {
    if (!/^[\x00-\x7f]*$/.test(value)) {
        throw new Asn1ParseError(`Invalid IA5String: ${value}`)
    }
    return primitive(UniversalTag.IA5String, latin1(value))
}

export function visibleString(value: string): Asn1Node {
    if (!/^[\x20-\x7e]*$/.test(value)) {
        throw new Asn1ParseError(`Invalid VisibleString: ${value}`)
    }
    return primitive(UniversalTag.VisibleString, latin1(value))
}

/** TeletexString (T61String), written as Latin-1 like most implementations. */
export function teletexString(value: string): Asn1Node {
    return primitive(UniversalTag.TeletexString, latin1(value))
}

/** BMPString: UTF-16BE, Basic Multilingual Plane only. */
export function bmpString(value: string): Asn1Node {
    const out = new Uint8Array(value.length * 2)
    for (let i = 0; i < value.length; i++) {
        const unit = value.charCodeAt(i)
        if (unit >= 0xd800 && unit <= 0xdfff) {
            throw new Asn1ParseError(
                'BMPString cannot hold characters outside the BMP',
            )
        }
        out[i * 2] = unit >> 8
        out[i * 2 + 1] = unit & 0xff
    }
    return primitive(UniversalTag.BMPString, out)
}

/** UniversalString: UTF-32BE. */
export function universalString(value: string): Asn1Node {
    const points = Array.from(value, (c) => c.codePointAt(0)!)
    const out = new Uint8Array(points.length * 4)
    const view = new DataView(out.buffer)
    points.forEach((p, i) => view.setUint32(i * 4, p))
    return primitive(UniversalTag.UniversalString, out)
}

/** UTCTime `YYMMDDHHMMSSZ`; only years 1950-2049 are representable. */
export function utcTime(date: Date): Asn1Node {
    const year = date.getUTCFullYear()
    if (year < 1950 || year > 2049) {
        throw new Asn1ParseError(`UTCTime cannot represent the year ${year}`)
    }
    return primitive(
        UniversalTag.UTCTime,
        latin1(pad(year % 100) + timeOfYear(date) + 'Z'),
    )
}

/** GeneralizedTime `YYYYMMDDHHMMSS[.fff]Z`, fraction without trailing zeros (DER). */
export function generalizedTime(date: Date): Asn1Node {
    const ms = date.getUTCMilliseconds()
    const fraction = ms ? '.' + pad(ms, 3).replace(/0+$/, '') : ''
    return primitive(
        UniversalTag.GeneralizedTime,
        latin1(
            pad(date.getUTCFullYear(), 4) + timeOfYear(date) + fraction + 'Z',
        ),
    )
}

const pad = (n: number, width = 2) => String(n).padStart(width, '0')

const timeOfYear = (d: Date) =>
    pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) +
    pad(d.getUTCHours()) +
    pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds())

function latin1(value: string): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(value.length)
    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i)
        if (code > 0xff) {
            throw new Asn1ParseError(`Character not representable: ${value[i]}`)
        }
        out[i] = code
    }
    return out
}
