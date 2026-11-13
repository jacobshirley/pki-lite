// Building and reading raw ASN.1 with the built-in DER codec

import {
    Asn1Node,
    der,
    derToAsn1,
    UniversalTag,
} from 'pki-lite/core/PkiBase.js'
import { Asn1ParseError } from 'pki-lite/core/errors/Asn1ParseError.js'

console.log('=== DER Codec Example ===\n')

// Build a structure from typed builders. Undefined entries (absent OPTIONAL
// fields) are skipped, and everything is encoded as DER.
//
//   Example ::= SEQUENCE {
//       id       OBJECT IDENTIFIER,
//       count    INTEGER,
//       label    [0] IMPLICIT UTF8String OPTIONAL,
//       created  [1] EXPLICIT GeneralizedTime }
const label: string | undefined = 'hello'
const node = der.sequence([
    der.oid('1.2.840.113549.1.7.1'),
    der.integer(2n ** 70n), // any size: numbers or bigints
    label === undefined ? undefined : der.utf8String(label).implicit(0),
    der.generalizedTime(new Date('2026-01-02T03:04:05Z')).explicit(1),
])

const bytes = node.encode()
console.log('Encoded:', bytes.length, 'bytes')
console.log(node.toString())

// Parse bytes back into a tree and read the typed values out of it
const parsed = Asn1Node.parse(bytes)
const [id, count, tagged, created] = parsed.items('Example')
console.log('\nid:', der.readOid(id))
console.log('count:', der.readBigInt(count))
// An IMPLICIT field is read back as its underlying type with retag()
if (tagged.isContext(0)) {
    console.log('label:', der.readString(tagged.retag(UniversalTag.UTF8String)))
}
// An EXPLICIT field wraps the value it tags
console.log('created:', der.readTime(created.children[0]).toISOString())

// A parsed value re-encodes to exactly the bytes it was parsed from
console.log(
    'Round-trips:',
    parsed.encode().every((b, i) => b === bytes[i]),
)

// Parsing is strict: truncated input, trailing bytes and bad lengths throw
for (const bad of [bytes.slice(0, -1), new Uint8Array([...bytes, 0])]) {
    try {
        derToAsn1(bad)
    } catch (e) {
        console.log('\nRejected:', (e as Asn1ParseError).message)
    }
}
