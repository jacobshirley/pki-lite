import { Asn1ParseError } from '../errors/Asn1ParseError.js'

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

const universalTagNames: Record<number, string> = Object.fromEntries(
    Object.entries(UniversalTag).map(([name, tag]) => [tag, name]),
)

/** Maximum nesting depth accepted by {@link Asn1Node.parse}. */
const MAX_DEPTH = 64

/**
 * A single ASN.1 TLV (tag, length, value).
 *
 * A node is either primitive (it has `content`) or constructed (it has `children`).
 * Nodes are immutable: re-tagging returns a new node. A node produced by
 * {@link Asn1Node.parse} remembers its original encoding, so `encode()` returns the
 * exact bytes that were parsed (needed to verify signatures over non-DER input);
 * nodes built in code are always encoded as DER with definite lengths.
 */
export class Asn1Node {
    readonly tagClass: TagClass
    readonly tag: number
    readonly constructed: boolean
    readonly content: Uint8Array<ArrayBuffer>
    readonly children: readonly Asn1Node[]

    private raw?: Uint8Array<ArrayBuffer>

    constructor(options: {
        tagClass?: TagClass
        tag: number
        content?: Uint8Array<ArrayBuffer>
        children?: readonly Asn1Node[]
    }) {
        const {
            tagClass = TagClass.Universal,
            tag,
            content,
            children,
        } = options
        if (content && children) {
            throw new Asn1ParseError(
                'An ASN.1 node has either content or children, not both',
            )
        }
        if (!Number.isSafeInteger(tag) || tag < 0) {
            throw new Asn1ParseError(`Invalid ASN.1 tag number: ${tag}`)
        }
        this.tagClass = tagClass
        this.tag = tag
        this.constructed = children !== undefined
        this.content = content ?? new Uint8Array(0)
        this.children = children ? [...children] : []
    }

    /**
     * Parses one BER/DER-encoded value. Indefinite lengths and constructed string
     * encodings are accepted; trailing bytes are an error.
     *
     * @throws Asn1ParseError if the input is not a single well-formed TLV
     */
    static parse(bytes: Uint8Array | ArrayBuffer): Asn1Node {
        const input = new Uint8Array(bytes as ArrayBuffer)
        const [node, end] = decode(input, 0, 0)
        if (end !== input.length) {
            throw new Asn1ParseError(
                `Unexpected ${input.length - end} trailing byte(s) after ASN.1 value`,
            )
        }
        return node
    }

    /** The encoded TLV: the parsed bytes for parsed nodes, DER otherwise. */
    encode(): Uint8Array<ArrayBuffer> {
        if (!this.raw) {
            this.raw = encode(this)
        }
        return this.raw
    }

    /** Whether this node has the given tag (universal by default). */
    is(tag: number, tagClass: TagClass = TagClass.Universal): boolean {
        return this.tag === tag && this.tagClass === tagClass
    }

    /** Whether this node carries the context-specific tag `[tag]`. */
    isContext(tag: number): boolean {
        return this.is(tag, TagClass.Context)
    }

    /**
     * Returns this node if it has the given tag, otherwise throws.
     *
     * @param what Description used in the error message, e.g. `'TBSCertificate'`
     */
    expect(tag: number, what?: string, tagClass = TagClass.Universal): this {
        if (!this.is(tag, tagClass)) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected ${what ?? describeTag(tagClass, tag)}, got ${this.describe()}`,
            )
        }
        return this
    }

    /** Returns this node's children, throwing if it is primitive. */
    items(what?: string): readonly Asn1Node[] {
        if (!this.constructed) {
            throw new Asn1ParseError(
                `Invalid ASN.1 structure: expected ${what ?? 'a constructed value'}, got primitive ${this.describe()}`,
            )
        }
        return this.children
    }

    /**
     * Returns the primitive content octets. A constructed (BER) string encoding is
     * flattened into a single value.
     */
    bytes(): Uint8Array<ArrayBuffer> {
        if (!this.constructed) {
            return this.content
        }
        const parts = this.children.map((child) => child.bytes())
        return concat(parts)
    }

    /**
     * Returns a copy of this node with an IMPLICIT tag: the tag is replaced, the
     * content (or children) are kept.
     */
    implicit(tag: number, tagClass: TagClass = TagClass.Context): Asn1Node {
        return this.constructed
            ? new Asn1Node({ tagClass, tag, children: this.children })
            : new Asn1Node({ tagClass, tag, content: this.content })
    }

    /** Wraps this node in an EXPLICIT tag: a constructed `[tag]` containing it. */
    explicit(tag: number, tagClass: TagClass = TagClass.Context): Asn1Node {
        return new Asn1Node({ tagClass, tag, children: [this] })
    }

    /**
     * Reinterprets this node under another tag. Used to read an IMPLICIT field as its
     * underlying type, e.g. `node.retag(UniversalTag.Sequence)`.
     */
    retag(tag: number, tagClass: TagClass = TagClass.Universal): Asn1Node {
        return this.implicit(tag, tagClass)
    }

    /** Short description of the tag, e.g. `SEQUENCE` or `[0]`. */
    describe(): string {
        return describeTag(this.tagClass, this.tag)
    }

    /** Indented dump of the tree, for debugging. */
    toString(indent = ''): string {
        const head = `${indent}${this.describe()}`
        if (this.constructed) {
            return [
                `${head} (${this.children.length} items)`,
                ...this.children.map((child) => child.toString(indent + '  ')),
            ].join('\n')
        }
        return `${head} ${toHex(this.content)}`
    }
}

function describeTag(tagClass: TagClass, tag: number): string {
    switch (tagClass) {
        case TagClass.Universal:
            return (universalTagNames[tag] ?? `UNIVERSAL ${tag}`)
                .replace(/([a-z])([A-Z])/g, '$1 $2')
                .toUpperCase()
        case TagClass.Application:
            return `[APPLICATION ${tag}]`
        case TagClass.Context:
            return `[${tag}]`
        case TagClass.Private:
            return `[PRIVATE ${tag}]`
    }
}

function decode(
    input: Uint8Array,
    start: number,
    depth: number,
): [Asn1Node, number] {
    if (depth > MAX_DEPTH) {
        throw new Asn1ParseError('ASN.1 value is nested too deeply')
    }

    let pos = start
    const byte = (): number => {
        if (pos >= input.length) {
            throw new Asn1ParseError('Unexpected end of ASN.1 data')
        }
        return input[pos++]
    }

    // Identifier octets
    const first = byte()
    const tagClass = (first >> 6) as TagClass
    const constructed = (first & 0x20) !== 0
    let tag = first & 0x1f
    if (tag === 0x1f) {
        tag = 0
        let b: number
        do {
            b = byte()
            tag = tag * 128 + (b & 0x7f)
            if (tag > Number.MAX_SAFE_INTEGER / 128) {
                throw new Asn1ParseError('ASN.1 tag number is too large')
            }
        } while (b & 0x80)
    }

    // Length octets
    let length: number | null
    const lb = byte()
    if (lb < 0x80) {
        length = lb
    } else if (lb === 0x80) {
        if (!constructed) {
            throw new Asn1ParseError(
                'Indefinite length is only allowed for constructed values',
            )
        }
        length = null
    } else {
        const count = lb & 0x7f
        if (count > 6) {
            throw new Asn1ParseError('ASN.1 length is too large')
        }
        length = 0
        for (let i = 0; i < count; i++) {
            length = length * 256 + byte()
        }
    }

    let node: Asn1Node
    let end: number

    if (length === null) {
        // Indefinite length: children until the end-of-contents octets (00 00)
        const children: Asn1Node[] = []
        for (;;) {
            if (pos + 1 >= input.length) {
                throw new Asn1ParseError(
                    'Missing end-of-contents in indefinite-length ASN.1 value',
                )
            }
            if (input[pos] === 0 && input[pos + 1] === 0) {
                pos += 2
                break
            }
            const [child, next] = decode(input, pos, depth + 1)
            children.push(child)
            pos = next
        }
        node = new Asn1Node({ tagClass, tag, children })
        end = pos
    } else {
        end = pos + length
        if (end > input.length) {
            throw new Asn1ParseError(
                `ASN.1 length ${length} exceeds the available data`,
            )
        }
        if (constructed) {
            const children: Asn1Node[] = []
            while (pos < end) {
                const [child, next] = decode(input, pos, depth + 1)
                if (next > end) {
                    throw new Asn1ParseError(
                        'ASN.1 child value overruns its parent',
                    )
                }
                children.push(child)
                pos = next
            }
            node = new Asn1Node({ tagClass, tag, children })
        } else {
            node = new Asn1Node({
                tagClass,
                tag,
                content: input.slice(pos, end),
            })
        }
    }

    ;(node as unknown as { raw: Uint8Array }).raw = input.slice(start, end)
    return [node, end]
}

function encode(node: Asn1Node): Uint8Array<ArrayBuffer> {
    const body = node.constructed
        ? concat(node.children.map((child) => child.encode()))
        : node.content
    return concat([
        encodeIdentifier(node.tagClass, node.constructed, node.tag),
        encodeLength(body.length),
        body,
    ])
}

function encodeIdentifier(
    tagClass: TagClass,
    constructed: boolean,
    tag: number,
): Uint8Array<ArrayBuffer> {
    const lead = (tagClass << 6) | (constructed ? 0x20 : 0)
    if (tag < 0x1f) {
        return new Uint8Array([lead | tag])
    }
    const digits: number[] = [tag % 128]
    for (let rest = Math.floor(tag / 128); rest > 0; ) {
        digits.unshift(rest % 128 | 0x80)
        rest = Math.floor(rest / 128)
    }
    return new Uint8Array([lead | 0x1f, ...digits])
}

function encodeLength(length: number): Uint8Array<ArrayBuffer> {
    if (length < 0x80) {
        return new Uint8Array([length])
    }
    const digits: number[] = []
    for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) {
        digits.unshift(rest % 256)
    }
    return new Uint8Array([0x80 | digits.length, ...digits])
}

/** Concatenates byte arrays. */
export function concat(parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
    let total = 0
    for (const part of parts) total += part.length
    const out = new Uint8Array(total)
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

function toHex(bytes: Uint8Array): string {
    let hex = ''
    for (const b of bytes) hex += b.toString(16).padStart(2, '0')
    return hex
}
