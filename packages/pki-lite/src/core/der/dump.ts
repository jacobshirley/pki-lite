import type { Asn1Node } from './Asn1Node.js'
import { TagClass, UniversalTag } from './tags.js'
import {
    readBigInt,
    readBitString,
    readBoolean,
    readOid,
    readString,
    readTime,
} from './readers.js'

const names: Record<number, string> = {
    [UniversalTag.Boolean]: 'BOOLEAN',
    [UniversalTag.Integer]: 'INTEGER',
    [UniversalTag.BitString]: 'BIT STRING',
    [UniversalTag.OctetString]: 'OCTET STRING',
    [UniversalTag.Null]: 'NULL',
    [UniversalTag.ObjectIdentifier]: 'OBJECT IDENTIFIER',
    [UniversalTag.Enumerated]: 'ENUMERATED',
    [UniversalTag.UTF8String]: 'UTF8String',
    [UniversalTag.Sequence]: 'SEQUENCE',
    [UniversalTag.Set]: 'SET',
    [UniversalTag.PrintableString]: 'PrintableString',
    [UniversalTag.TeletexString]: 'TeletexString',
    [UniversalTag.IA5String]: 'IA5String',
    [UniversalTag.UTCTime]: 'UTCTime',
    [UniversalTag.GeneralizedTime]: 'GeneralizedTime',
    [UniversalTag.VisibleString]: 'VisibleString',
    [UniversalTag.UniversalString]: 'UniversalString',
    [UniversalTag.BMPString]: 'BmpString',
}

const stringTags = new Set<number>([
    UniversalTag.UTF8String,
    UniversalTag.PrintableString,
    UniversalTag.TeletexString,
    UniversalTag.IA5String,
    UniversalTag.VisibleString,
    UniversalTag.UniversalString,
    UniversalTag.BMPString,
])

/**
 * Renders a node tree as indented text, one `TYPE : value` line per node, e.g.
 *
 * ```
 * SEQUENCE :
 *   OBJECT IDENTIFIER : 1.2.840.113549.1.1.11
 *   NULL
 * ```
 *
 * Values that cannot be decoded (malformed content) are shown as hex.
 */
export function dump(node: Asn1Node, indent = ''): string {
    const universal = node.tagClass === TagClass.Universal
    const name = universal
        ? (names[node.tag] ?? `UNIVERSAL ${node.tag}`)
        : node.tagClass === TagClass.Context
          ? `[${node.tag}]`
          : node.describe()

    // Constructed (BER) strings are shown as their flattened value
    const isString =
        universal &&
        (stringTags.has(node.tag) ||
            node.tag === UniversalTag.OctetString ||
            node.tag === UniversalTag.BitString)
    if (node.constructed && !isString) {
        return [
            `${indent}${name} :`,
            ...node.children.map((child) => dump(child, indent + '  ')),
        ].join('\n')
    }
    if (universal && node.tag === UniversalTag.Null) {
        return `${indent}NULL`
    }
    if (universal && node.tag === UniversalTag.Boolean) {
        return `${indent}BOOLEAN: ${attempt(() => (readBoolean(node) ? 'TRUE' : 'FALSE'), node)}`
    }
    return `${indent}${name} : ${universal ? value(node) : hex(node.bytes())}`
}

function value(node: Asn1Node): string {
    return attempt(() => {
        switch (node.tag) {
            case UniversalTag.Integer:
                return readBigInt(node).toString()
            case UniversalTag.Enumerated:
                return readBigInt(node.retag(UniversalTag.Integer)).toString()
            case UniversalTag.ObjectIdentifier:
                return readOid(node)
            case UniversalTag.BitString: {
                const { bytes, unusedBits } = readBitString(node)
                let bits = ''
                for (const b of bytes) bits += b.toString(2).padStart(8, '0')
                return bits.slice(0, bits.length - unusedBits)
            }
            case UniversalTag.UTCTime:
            case UniversalTag.GeneralizedTime:
                return readTime(node).toISOString()
        }
        if (stringTags.has(node.tag)) {
            return `'${readString(node)}'`
        }
        return hex(node.bytes())
    }, node)
}

function attempt(fn: () => string, node: Asn1Node): string {
    try {
        return fn()
    } catch {
        return hex(node.bytes())
    }
}

function hex(bytes: Uint8Array): string {
    let out = ''
    for (const b of bytes) out += b.toString(16).padStart(2, '0')
    return out
}
