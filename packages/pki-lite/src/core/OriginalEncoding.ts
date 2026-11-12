import { Asn1BaseBlock, PkiBase } from './PkiBase.js'

/** Hidden storage: the bytes a value was parsed from, and its encoding at that time. */
const ORIGINAL = Symbol('pki-lite original encoding')

type Remembered = {
    original: Uint8Array<ArrayBuffer>
    reencoded: Uint8Array<ArrayBuffer>
}

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
    a.length === b.length && a.every((byte, i) => byte === b[i])

/**
 * Remembers the exact bytes a structure was parsed from, so that a signature over it
 * (the TBSCertificate of a certificate, the TBSCertList of a CRL, ...) can be verified
 * against what was actually signed. Re-encoding a parsed value does not always give the
 * same bytes back (a GeneralizedTime before 2050 becomes a UTCTime, a string changes
 * type, ...), and any difference breaks the signature.
 *
 * Stored as a non-enumerable property, so it takes no part in JSON or equality.
 */
export function rememberOriginalEncoding(
    target: PkiBase,
    parsed: Asn1BaseBlock,
): void {
    const view = parsed.valueBeforeDecodeView
    if (!view || view.byteLength === 0) return
    const remembered: Remembered = {
        original: new Uint8Array(view),
        reencoded: target.toDer(),
    }
    Object.defineProperty(target, ORIGINAL, {
        value: remembered,
        enumerable: false,
        configurable: true,
        writable: true,
    })
}

/**
 * The bytes a signature over `target` covers: the bytes it was parsed from, unless it has
 * been changed since (its encoding no longer matches the one it had when parsed), in which
 * case its current encoding.
 */
export function signedBytes(target: PkiBase): Uint8Array<ArrayBuffer> {
    const current = target.toDer()
    const remembered = (target as unknown as { [ORIGINAL]?: Remembered })[
        ORIGINAL
    ]
    if (remembered && sameBytes(current, remembered.reencoded)) {
        return remembered.original
    }
    return current
}
